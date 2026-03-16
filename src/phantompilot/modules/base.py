"""Abstract base class for test modules."""

from __future__ import annotations
from abc import ABC, abstractmethod
from phantompilot.adapters.base import AgentAdapter
from phantompilot.models import ASICode, Finding


class ModuleError(Exception):
    """Base exception for test module errors."""

class ModuleSetupError(ModuleError):
    """Raised when a module fails to set up preconditions."""


class TestModule(ABC):
    """Base class for OWASP Agentic AI security test modules.
    Lifecycle: setup() -> execute() -> teardown().
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def asi_code(self) -> ASICode: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def atlas_technique_ids(self) -> list[str]: ...

    @abstractmethod
    async def setup(self) -> None: ...

    @abstractmethod
    async def execute(self, adapter: AgentAdapter) -> list[Finding]: ...

    @abstractmethod
    async def teardown(self) -> None: ...

    def classify_severity(self, success_rate: float, blast_radius: float) -> str:
        score = (success_rate * 6) + (blast_radius * 0.4)
        if score >= 8.0: return "critical"
        if score >= 6.0: return "high"
        if score >= 4.0: return "medium"
        if score >= 2.0: return "low"
        return "info"
