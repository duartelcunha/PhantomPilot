"""LangChain agent adapter."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from phantompilot.adapters.base import AdapterConnectionError, AdapterTimeoutError, AgentAdapter
from phantompilot.models import AgentMemory, AgentResponse, AgentState, MemoryEntry, ToolCall

logger = logging.getLogger(__name__)
__all__ = ["LangChainAdapter"]


class _ToolCallCollector:
    def __init__(self) -> None:
        self.calls: list[ToolCall] = []

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self.calls.append(ToolCall(tool_name=str(name), arguments={"input": input_str}, result=None))

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if self.calls:
            last = self.calls[-1]
            self.calls[-1] = ToolCall(tool_name=last.tool_name, arguments=last.arguments, result=str(output), timestamp=last.timestamp)

    def clear(self) -> None:
        self.calls.clear()


def _extract_tool_calls_from_steps(steps: list[tuple[Any, str]]) -> list[ToolCall]:
    results: list[ToolCall] = []
    for action, observation in steps:
        tn = getattr(action, "tool", "unknown")
        ti = getattr(action, "tool_input", "")
        args: dict[str, Any] = ti if isinstance(ti, dict) else {"input": str(ti)}
        results.append(ToolCall(tool_name=str(tn), arguments=args, result=str(observation)))
    return results


class LangChainAdapter(AgentAdapter):
    def __init__(self, agent_executor: Any, input_key: str = "input", timeout_seconds: float = 60.0) -> None:
        self._executor = agent_executor
        self._input_key = input_key
        self._timeout = timeout_seconds
        self._collector = _ToolCallCollector()
        self._all_tool_calls: list[ToolCall] = []
        self._history: list[dict[str, str]] = []
        cbs: list[Any] = getattr(self._executor, "callbacks", None) or []
        if not isinstance(cbs, list):
            cbs = list(cbs)
        cbs.append(self._collector)
        self._executor.callbacks = cbs  # type: ignore[attr-defined]

    async def send_message(self, message: str) -> AgentResponse:
        self._collector.clear()
        inp = {self._input_key: message}
        start = time.monotonic()
        try:
            if hasattr(self._executor, "ainvoke"):
                raw = await asyncio.wait_for(self._executor.ainvoke(inp), timeout=self._timeout)
            else:
                raw = await asyncio.wait_for(asyncio.get_event_loop().run_in_executor(None, self._executor.invoke, inp), timeout=self._timeout)
        except asyncio.TimeoutError as e:
            raise AdapterTimeoutError(f"Timeout after {self._timeout}s") from e
        except Exception as e:
            if "connection" in str(e).lower():
                raise AdapterConnectionError(str(e)) from e
            raise
        elapsed = (time.monotonic() - start) * 1000
        rd = raw if isinstance(raw, dict) else {"output": str(raw)}
        out = str(rd.get("output", rd.get("result", "")))
        sc = _extract_tool_calls_from_steps(rd.get("intermediate_steps", []))
        tcs = sc if sc else list(self._collector.calls)
        self._all_tool_calls.extend(tcs)
        self._history.append({"role": "user", "content": message})
        self._history.append({"role": "assistant", "content": out})
        return AgentResponse(content=out, tool_calls=tcs, raw=rd, latency_ms=elapsed)

    async def get_tool_calls(self) -> list[ToolCall]:
        return list(self._all_tool_calls)

    async def get_memory(self) -> AgentMemory:
        mem = getattr(self._executor, "memory", None)
        if mem is None:
            return AgentMemory(memory_type="none", entries=[], total_entries=0)
        entries: list[MemoryEntry] = []
        mt = type(mem).__name__
        if hasattr(mem, "chat_memory") and hasattr(mem.chat_memory, "messages"):
            for m in mem.chat_memory.messages:
                entries.append(MemoryEntry(content=str(getattr(m, "content", str(m))), entry_type="conversation"))
        if hasattr(mem, "buffer") and isinstance(getattr(mem, "buffer"), str) and mem.buffer.strip():
            entries.append(MemoryEntry(content=mem.buffer, entry_type="summary"))
        if hasattr(mem, "retriever"):
            entries.append(MemoryEntry(content="[vector store memory]", entry_type="vector"))
        return AgentMemory(entries=entries, memory_type=mt, total_entries=len(entries))

    async def get_agent_state(self) -> AgentState:
        tools: list[str] = [getattr(t, "name", str(t)) for t in getattr(self._executor, "tools", [])]
        sp = ""
        ai = getattr(self._executor, "agent", None)
        if ai:
            p = getattr(ai, "prompt", None) or getattr(ai, "first", None)
            if p and hasattr(p, "messages"):
                for mt in p.messages:
                    if hasattr(mt, "prompt") and hasattr(mt.prompt, "template"):
                        sp = mt.prompt.template
                        break
        mn = ""
        llm = getattr(self._executor, "llm", None) or getattr(getattr(self._executor, "agent", None), "llm", None)
        if llm:
            mn = str(getattr(llm, "model_name", getattr(llm, "model", "")))
        return AgentState(available_tools=tools, system_prompt=sp, model_name=mn,
            metadata={"executor_type": type(self._executor).__name__, "has_memory": hasattr(self._executor, "memory") and self._executor.memory is not None})

    async def reset(self) -> None:
        self._all_tool_calls.clear()
        self._collector.clear()
        self._history.clear()
        mem = getattr(self._executor, "memory", None)
        if mem and hasattr(mem, "clear"):
            mem.clear()

    async def health_check(self) -> bool:
        try:
            return hasattr(self._executor, "invoke") or hasattr(self._executor, "ainvoke")
        except Exception:
            return False
