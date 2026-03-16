"""CrewAI adapter."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from phantompilot.adapters.base import AdapterConnectionError, AdapterTimeoutError, AgentAdapter
from phantompilot.models import AgentMemory, AgentResponse, AgentState, MemoryEntry, ToolCall

logger = logging.getLogger(__name__)
__all__ = ["CrewAIAdapter"]


class CrewAIAdapter(AgentAdapter):
    def __init__(self, crew: Any, timeout_seconds: float = 120.0) -> None:
        self._crew = crew
        self._timeout = timeout_seconds
        self._all_tool_calls: list[ToolCall] = []
        self._history: list[dict[str, str]] = []
        self._delegation_chains: list[list[dict[str, str]]] = []

    async def send_message(self, message: str) -> AgentResponse:
        start = time.monotonic()
        try:
            kf = getattr(self._crew, "kickoff_async", None)
            inputs = {"message": message, "input": message}
            if kf:
                raw = await asyncio.wait_for(kf(inputs=inputs), timeout=self._timeout)
            else:
                raw = await asyncio.wait_for(asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._crew.kickoff(inputs=inputs)), timeout=self._timeout)
        except asyncio.TimeoutError as e:
            raise AdapterTimeoutError(str(e)) from e
        except Exception as e:
            if "connection" in str(e).lower():
                raise AdapterConnectionError(str(e)) from e
            raise
        elapsed = (time.monotonic() - start) * 1000
        out = str(getattr(raw, "raw", raw))
        self._history.append({"role": "user", "content": message})
        self._history.append({"role": "assistant", "content": out})
        return AgentResponse(content=out, tool_calls=[], raw={"output": out}, latency_ms=elapsed)

    async def get_tool_calls(self) -> list[ToolCall]:
        return list(self._all_tool_calls)

    async def get_memory(self) -> AgentMemory:
        entries: list[MemoryEntry] = []
        for i, chain in enumerate(self._delegation_chains):
            entries.append(MemoryEntry(content=str(chain), entry_type="custom",
                metadata={"source": "delegation_chain", "kickoff_index": i}))
        return AgentMemory(entries=entries, memory_type="crewai_composite", total_entries=len(entries))

    async def get_agent_state(self) -> AgentState:
        tools: list[str] = []
        agents_info: list[dict[str, str]] = []
        agents = getattr(self._crew, "agents", [])
        for a in agents:
            nm = str(getattr(a, "role", "unknown"))
            at = getattr(a, "tools", [])
            tn = [getattr(t, "name", str(t)) for t in at]
            tools.extend(tn)
            agents_info.append({"role": nm, "goal": str(getattr(a, "goal", "")),
                "tools": str(tn), "allow_delegation": str(getattr(a, "allow_delegation", False))})
        pt = str(getattr(self._crew, "process", "sequential"))
        mn = ""
        if agents:
            llm = getattr(agents[0], "llm", None)
            if llm:
                mn = str(getattr(llm, "model_name", getattr(llm, "model", "")))
        return AgentState(available_tools=list(set(tools)), system_prompt="", model_name=mn,
            metadata={"process_type": pt, "agent_count": len(agents), "agents": agents_info,
                "task_count": len(getattr(self._crew, "tasks", []))})

    async def reset(self) -> None:
        self._all_tool_calls.clear()
        self._history.clear()
        self._delegation_chains.clear()

    async def health_check(self) -> bool:
        try:
            return bool(getattr(self._crew, "agents", []) and getattr(self._crew, "tasks", []))
        except Exception:
            return False
