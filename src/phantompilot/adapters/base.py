"""Abstract base class for agent adapters."""

from __future__ import annotations
from abc import ABC, abstractmethod
from phantompilot.models import AgentMemory, AgentResponse, AgentState, ToolCall


class AdapterError(Exception):
    """Base exception for all adapter errors."""

class AdapterConnectionError(AdapterError):
    """Raised when the adapter cannot reach the target agent."""

class AdapterTimeoutError(AdapterError):
    """Raised when an adapter operation exceeds its timeout."""


class AgentAdapter(ABC):
    """Unified interface for interacting with AI agents across frameworks."""

    @abstractmethod
    async def send_message(self, message: str) -> AgentResponse:
        """Send a text message to the agent and return its response."""

    @abstractmethod
    async def get_tool_calls(self) -> list[ToolCall]:
        """Return all tool calls made during the current session."""

    @abstractmethod
    async def get_memory(self) -> AgentMemory:
        """Retrieve a snapshot of the agent's current memory state."""

    @abstractmethod
    async def get_agent_state(self) -> AgentState:
        """Retrieve the agent's current configuration and capabilities."""

    @abstractmethod
    async def reset(self) -> None:
        """Reset the adapter to a clean state."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify that the target agent is reachable and responsive."""
