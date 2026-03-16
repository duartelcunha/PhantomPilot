"""Core data models, enums, and type aliases for PhantomPilot."""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

EvidenceChain = list[dict[str, Any]]
Metadata = dict[str, Any]
PayloadSet = list[str]


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ASICode(Enum):
    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"


class AdapterType(Enum):
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    REST = "rest"
    CUSTOM = "custom"


class ReportFormat(Enum):
    JSON = "json"
    HTML = "html"
    ATLAS = "atlas"


class ModuleStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]
    result: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class AgentResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class MemoryEntry:
    content: str
    entry_type: str
    metadata: Metadata = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class AgentMemory:
    entries: list[MemoryEntry] = field(default_factory=list)
    memory_type: str = "unknown"
    total_entries: int = 0


@dataclass(frozen=True)
class AgentState:
    available_tools: list[str] = field(default_factory=list)
    system_prompt: str = ""
    model_name: str = ""
    temperature: float = 0.0
    max_tokens: int = 0
    metadata: Metadata = field(default_factory=dict)


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    asi_code: ASICode
    evidence_chain: EvidenceChain
    atlas_technique_id: str
    recommendation: str
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Metadata = field(default_factory=dict)


@dataclass
class ModuleResult:
    module_name: str
    asi_code: ASICode
    status: ModuleStatus
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error_message: str | None = None


@dataclass
class MetricsReport:
    total_modules_run: int
    total_findings: int
    attack_success_rate: float
    per_module_asr: dict[str, float] = field(default_factory=dict)
    avg_time_to_compromise_seconds: float = 0.0
    blast_radius_score: float = 0.0
    severity_distribution: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    target_type: AdapterType
    target_info: str
    module_results: list[ModuleResult] = field(default_factory=list)
    metrics: MetricsReport | None = None
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    config_snapshot: Metadata = field(default_factory=dict)
