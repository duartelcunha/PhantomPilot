import pytest
from phantompilot.models import ASICode, AgentState
from phantompilot.modules.asi02_tool_misuse import ToolMisuseModule
from tests.conftest import MockAdapter, MockAgent

class TestBasic:
    @pytest.mark.asyncio
    async def test_loads(self): m = ToolMisuseModule(); await m.setup(); assert len(m._probes) > 0
    @pytest.mark.asyncio
    async def test_no_tools(self):
        a = MockAgent(); a.state = AgentState(available_tools=[])
        m = ToolMisuseModule(); await m.setup(); assert await m.execute(MockAdapter(a)) == []

class TestVuln:
    @pytest.mark.asyncio
    async def test_detects(self, vulnerable_adapter):
        m = ToolMisuseModule(); await m.setup()
        f = await m.execute(vulnerable_adapter); assert len(f) > 0 and all(x.asi_code == ASICode.ASI02 for x in f)
    @pytest.mark.asyncio
    async def test_meta(self, vulnerable_adapter):
        m = ToolMisuseModule(); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert "probe_name" in f.metadata or "target_tool" in f.metadata

class TestSafe:
    @pytest.mark.asyncio
    async def test_none(self, safe_adapter): m = ToolMisuseModule(); await m.setup(); assert await m.execute(safe_adapter) == []

class TestTeardown:
    @pytest.mark.asyncio
    async def test_clears(self): m = ToolMisuseModule(); await m.setup(); await m.teardown(); assert m._probes == []
