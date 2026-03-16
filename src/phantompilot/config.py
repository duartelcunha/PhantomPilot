"""YAML configuration loading and validation."""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml
from phantompilot.models import ASICode, AdapterType, ReportFormat

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


@dataclass
class AdapterConfig:
    adapter_type: AdapterType
    module_path: str | None = None
    class_name: str | None = None
    init_kwargs: dict[str, Any] = field(default_factory=dict)
    base_url: str | None = None
    auth_type: str | None = None
    auth_value: str | None = None
    endpoints: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0


@dataclass
class ModuleConfig:
    asi_code: ASICode
    enabled: bool = True
    custom_payloads: list[str] = field(default_factory=list)
    max_turns: int = 10
    timeout_seconds: float = 120.0
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportConfig:
    formats: list[ReportFormat] = field(default_factory=lambda: [ReportFormat.JSON])
    output_dir: str = "./reports"
    include_evidence: bool = True
    include_recommendations: bool = True


@dataclass
class ScanConfig:
    adapter: AdapterConfig
    modules: list[ModuleConfig] = field(default_factory=list)
    report: ReportConfig = field(default_factory=ReportConfig)
    concurrency: int = 1
    verbose: bool = False


_VALID_AUTH_TYPES = {"bearer", "api_key", "none"}


def validate_config(config: ScanConfig) -> list[str]:
    errors: list[str] = []
    if config.adapter.adapter_type == AdapterType.REST:
        if not config.adapter.base_url:
            errors.append("REST adapter requires 'base_url' to be set.")
        if not config.adapter.auth_type:
            errors.append("REST adapter requires 'auth_type' to be set.")
        if config.adapter.auth_type and config.adapter.auth_type not in _VALID_AUTH_TYPES:
            errors.append(f"Invalid auth_type '{config.adapter.auth_type}'.")
    elif config.adapter.adapter_type in (AdapterType.LANGCHAIN, AdapterType.CREWAI):
        if not config.adapter.module_path or not config.adapter.class_name:
            errors.append(f"{config.adapter.adapter_type.value} adapter requires 'module_path' and 'class_name'.")
    if config.adapter.timeout_seconds <= 0:
        errors.append("Adapter timeout must be positive.")
    seen: set[ASICode] = set()
    for mod in config.modules:
        if mod.asi_code in seen:
            errors.append(f"Duplicate module entry for {mod.asi_code.value}.")
        seen.add(mod.asi_code)
        if mod.max_turns < 1:
            errors.append(f"{mod.asi_code.value}: max_turns must be >= 1.")
        if mod.timeout_seconds <= 0:
            errors.append(f"{mod.asi_code.value}: timeout must be positive.")
    if not config.report.formats:
        errors.append("At least one report format must be specified.")
    if config.concurrency < 1:
        errors.append("Concurrency must be >= 1.")
    return errors


def _parse_adapter(raw: dict[str, Any]) -> AdapterConfig:
    t = raw.get("type", "")
    try:
        at = AdapterType(t)
    except ValueError:
        raise ConfigError(f"Unknown adapter type '{t}'. Valid: {[x.value for x in AdapterType]}")
    return AdapterConfig(adapter_type=at, module_path=raw.get("module_path"), class_name=raw.get("class_name"),
        init_kwargs=raw.get("init_kwargs", {}), base_url=raw.get("base_url"), auth_type=raw.get("auth_type"),
        auth_value=raw.get("auth_value"), endpoints=raw.get("endpoints", {}), timeout_seconds=float(raw.get("timeout_seconds", 30.0)))


def _parse_modules(raw_list: list[dict[str, Any]]) -> list[ModuleConfig]:
    modules: list[ModuleConfig] = []
    for entry in raw_list:
        cs = entry.get("asi_code", "")
        try:
            code = ASICode(cs)
        except ValueError:
            raise ConfigError(f"Unknown ASI code '{cs}'.")
        modules.append(ModuleConfig(asi_code=code, enabled=entry.get("enabled", True), custom_payloads=entry.get("custom_payloads", []),
            max_turns=int(entry.get("max_turns", 10)), timeout_seconds=float(entry.get("timeout_seconds", 120.0)), parameters=entry.get("parameters", {})))
    return modules


def _parse_report(raw: dict[str, Any]) -> ReportConfig:
    fmts = []
    for fs in raw.get("formats", ["json"]):
        try:
            fmts.append(ReportFormat(fs))
        except ValueError:
            raise ConfigError(f"Unknown report format '{fs}'.")
    return ReportConfig(formats=fmts, output_dir=raw.get("output_dir", "./reports"),
        include_evidence=raw.get("include_evidence", True), include_recommendations=raw.get("include_recommendations", True))


def load_config(path: str | Path) -> ScanConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Configuration file must contain a YAML mapping at the top level.")
    if "adapter" not in raw:
        raise ConfigError("Configuration must include an 'adapter' section.")
    adapter = _parse_adapter(raw["adapter"])
    modules = _parse_modules(raw.get("modules", []))
    report = _parse_report(raw.get("report", {}))
    config = ScanConfig(adapter=adapter, modules=modules, report=report,
        concurrency=int(raw.get("concurrency", 1)), verbose=bool(raw.get("verbose", False)))
    errors = validate_config(config)
    if errors:
        raise ConfigError("Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors))
    return config
