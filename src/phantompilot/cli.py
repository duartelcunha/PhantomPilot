"""PhantomPilot CLI entrypoint."""

from __future__ import annotations
import logging, sys
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from phantompilot.config import ConfigError, load_config, validate_config
from phantompilot.models import ASICode

console = Console()

_MODULE_DESCRIPTIONS: dict[ASICode, tuple[str, str]] = {
    ASICode.ASI01: ("Prompt Injection", "Multi-turn goal hijacking and instruction override"),
    ASICode.ASI02: ("Tool Misuse", "Unauthorized tool invocation and cross-tool chaining"),
    ASICode.ASI03: ("Excessive Permissions", "Privilege escalation via tool boundaries"),
    ASICode.ASI04: ("Output Validation", "XSS, SQLi, and command injection in agent output"),
    ASICode.ASI05: ("Output Consumption", "SSRF, template injection in downstream consumers"),
    ASICode.ASI06: ("Memory Poisoning", "Canary token injection and cross-session propagation"),
    ASICode.ASI07: ("Supply Chain", "Third-party plugin and tool risk assessment"),
    ASICode.ASI08: ("Overreliance", "Confidence calibration and epistemic humility testing"),
    ASICode.ASI09: ("Inter-Agent Comms", "Delegation chain spoofing and message tampering"),
    ASICode.ASI10: ("Rogue Agent", "Behavioral drift and deceptive alignment detection"),
}


@click.group()
@click.version_option(package_name="phantompilot")
def main() -> None:
    """PhantomPilot — AI Agent Red Team Framework."""


@main.command("list-modules")
def list_modules() -> None:
    """List all available test modules."""
    table = Table(title="PhantomPilot Test Modules")
    table.add_column("ASI Code", style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    for code in ASICode:
        name, desc = _MODULE_DESCRIPTIONS[code]
        table.add_row(code.value, name, desc)
    console.print(table)


@main.command("validate-config")
@click.option("--config", "-c", required=True, type=click.Path(exists=True))
def validate_config_cmd(config: str) -> None:
    """Validate a configuration file."""
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise SystemExit(1)
    errors = validate_config(cfg)
    if errors:
        console.print("[red]Validation failed:[/red]")
        for err in errors:
            console.print(f"  - {err}")
        raise SystemExit(1)
    console.print(f"[green]Configuration is valid.[/green] {len(cfg.modules)} modules configured.")


@main.command("scan")
@click.option("--config", "-c", required=True, type=click.Path(exists=True))
@click.option("--target", "-t", type=click.Choice(["langchain", "crewai", "rest", "custom"]), default=None)
@click.option("--modules", "-m", default=None, help="Comma-separated ASI codes.")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--dry-run", is_flag=True, default=False)
def scan(config: str, target: str | None, modules: str | None, verbose: bool, dry_run: bool) -> None:
    """Execute a security scan against a target AI agent."""
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise SystemExit(1)
    if target:
        from phantompilot.models import AdapterType
        cfg.adapter.adapter_type = AdapterType(target)
    if modules:
        requested = set(modules.upper().split(","))
        unknown = requested - {c.value for c in ASICode}
        if unknown:
            console.print(f"[red]Unknown module codes:[/red] {", ".join(sorted(unknown))}")
            raise SystemExit(1)
        cfg.modules = [m for m in cfg.modules if m.asi_code.value in requested]
    enabled = [m for m in cfg.modules if m.enabled]
    console.print(f"[bold]PhantomPilot scan[/bold] — {len(enabled)} modules, target: {cfg.adapter.adapter_type.value}")
    if dry_run:
        console.print("[yellow]Dry run — no scan executed.[/yellow]")
        for mod in enabled:
            name, _ = _MODULE_DESCRIPTIONS[mod.asi_code]
            console.print(f"  [{mod.asi_code.value}] {name}")
        return
    console.print("[yellow]Scan execution requires module implementations.[/yellow]")
