from unittest.mock import MagicMock
import pytest
from phantompilot.adapters.langchain import LangChainAdapter

class FakeExec:
    def __init__(self, response="Hello!", tools=None):
        self.response, self.tools, self.callbacks, self.memory = response, tools or [], [], None
    def invoke(self, inputs): return {"output": self.response, "intermediate_steps": []}

class FakeAsync(FakeExec):
    async def ainvoke(self, inputs): return {"output": self.response, "intermediate_steps": []}

class TestLC:
    @pytest.mark.asyncio
    async def test_sync(self): assert (await LangChainAdapter(FakeExec("OK")).send_message("Hi")).content == "OK"
    @pytest.mark.asyncio
    async def test_async(self): assert (await LangChainAdapter(FakeAsync("Async")).send_message("Hi")).content == "Async"
    @pytest.mark.asyncio
    async def test_tools(self):
        t = MagicMock(); t.name = "search"
        assert "search" in (await LangChainAdapter(FakeExec(tools=[t])).get_agent_state()).available_tools
    @pytest.mark.asyncio
    async def test_health_ok(self): assert await LangChainAdapter(FakeExec()).health_check() is True
    @pytest.mark.asyncio
    async def test_health_bad(self): assert await LangChainAdapter(object()).health_check() is False  # type: ignore
    @pytest.mark.asyncio
    async def test_reset(self):
        a = LangChainAdapter(FakeExec()); await a.send_message("t"); await a.reset(); assert await a.get_tool_calls() == []
    @pytest.mark.asyncio
    async def test_no_memory(self): assert (await LangChainAdapter(FakeExec()).get_memory()).memory_type == "none"
