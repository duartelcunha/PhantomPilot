"""REST adapter — generic HTTP client for agents exposed via API endpoints."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from phantompilot.adapters.base import AdapterConnectionError, AdapterTimeoutError, AgentAdapter
from phantompilot.models import AgentMemory, AgentResponse, AgentState, MemoryEntry, ToolCall

logger = logging.getLogger(__name__)
__all__ = ["RESTAdapter"]


def _resolve_jsonpath(data: Any, path: str) -> Any:
    current: Any = data
    for seg in path.split("."):
        if current is None:
            return None
        if seg == "*":
            return current if isinstance(current, list) else None
        if isinstance(current, dict):
            current = current.get(seg)
        elif isinstance(current, list):
            try:
                current = current[int(seg)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


class RESTAdapter(AgentAdapter):
    def __init__(self, base_url: str, auth_type: str = "none", auth_value: str = "",
                 endpoints: dict[str, str] | None = None,
                 response_paths: dict[str, str] | None = None,
                 timeout_seconds: float = 30.0, max_retries: int = 2) -> None:
        self._base_url = base_url.rstrip("/")
        self._endpoints = endpoints or {"send_message": "/chat", "get_state": "/state",
            "get_memory": "/memory", "health": "/health"}
        self._response_paths = response_paths or {"content": "response", "tool_calls": "tool_calls",
            "tool_name": "name", "tool_args": "arguments", "tool_result": "result",
            "memory_entries": "entries", "tools": "tools", "system_prompt": "system_prompt",
            "model_name": "model"}
        self._timeout = timeout_seconds
        self._all_tool_calls: list[ToolCall] = []
        self._session_id: str | None = None

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if auth_type == "bearer" and auth_value:
            headers["Authorization"] = f"Bearer {auth_value}"
        elif auth_type == "api_key" and auth_value:
            headers["X-API-Key"] = auth_value

        transport = httpx.AsyncHTTPTransport(retries=max_retries)
        self._client = httpx.AsyncClient(base_url=self._base_url, headers=headers,
            timeout=httpx.Timeout(timeout_seconds), transport=transport)

    def _extract(self, data: Any, key: str) -> Any:
        return _resolve_jsonpath(data, self._response_paths.get(key, key))

    async def _request(self, method: str, op: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self._endpoints.get(op, f"/{op}")
        try:
            response = await self._client.request(method, url, json=json_body)
        except httpx.ConnectError as exc:
            raise AdapterConnectionError(f"Cannot connect to {self._base_url}{url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise AdapterTimeoutError(f"Timed out: {exc}") from exc
        if response.status_code >= 500:
            raise AdapterConnectionError(f"Server error {response.status_code} from {url}: {response.text[:500]}")
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        if "session_id" in result:
            self._session_id = str(result["session_id"])
        return result

    async def send_message(self, message: str) -> AgentResponse:
        body: dict[str, Any] = {"message": message}
        if self._session_id:
            body["session_id"] = self._session_id
        start = time.monotonic()
        raw = await self._request("POST", "send_message", json_body=body)
        elapsed_ms = (time.monotonic() - start) * 1000
        content = str(self._extract(raw, "content") or "")
        tool_calls: list[ToolCall] = []
        raw_calls = self._extract(raw, "tool_calls")
        if isinstance(raw_calls, list):
            for cd in raw_calls:
                if isinstance(cd, dict):
                    tool_calls.append(ToolCall(
                        tool_name=str(cd.get(self._response_paths.get("tool_name", "name"), "unknown")),
                        arguments=cd.get(self._response_paths.get("tool_args", "arguments"), {}),
                        result=cd.get(self._response_paths.get("tool_result", "result"))))
        self._all_tool_calls.extend(tool_calls)
        return AgentResponse(content=content, tool_calls=tool_calls, raw=raw, latency_ms=elapsed_ms)

    async def get_tool_calls(self) -> list[ToolCall]:
        return list(self._all_tool_calls)

    async def get_memory(self) -> AgentMemory:
        try:
            raw = await self._request("GET", "get_memory")
        except (AdapterConnectionError, AdapterTimeoutError, httpx.HTTPStatusError):
            return AgentMemory(memory_type="rest_unavailable", entries=[], total_entries=0)
        entries: list[MemoryEntry] = []
        raw_entries = self._extract(raw, "memory_entries")
        if isinstance(raw_entries, list):
            for ed in raw_entries:
                if isinstance(ed, dict):
                    entries.append(MemoryEntry(content=str(ed.get("content", "")), entry_type=str(ed.get("type", "custom")),
                        metadata={k: v for k, v in ed.items() if k not in ("content", "type")}))
                else:
                    entries.append(MemoryEntry(content=str(ed), entry_type="custom"))
        return AgentMemory(entries=entries, memory_type="rest", total_entries=len(entries))

    async def get_agent_state(self) -> AgentState:
        try:
            raw = await self._request("GET", "get_state")
        except (AdapterConnectionError, AdapterTimeoutError, httpx.HTTPStatusError):
            return AgentState()
        tools_raw = self._extract(raw, "tools")
        tools: list[str] = []
        if isinstance(tools_raw, list):
            tools = [str(t) if isinstance(t, str) else str(t.get("name", t)) for t in tools_raw]
        return AgentState(available_tools=tools,
            system_prompt=str(self._extract(raw, "system_prompt") or ""),
            model_name=str(self._extract(raw, "model_name") or ""), metadata=raw)

    async def reset(self) -> None:
        self._all_tool_calls.clear()
        self._session_id = None
        if "reset" in self._endpoints:
            try:
                await self._request("POST", "reset", json_body={})
            except Exception:
                pass

    async def health_check(self) -> bool:
        try:
            await self._request("GET", "health")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()
