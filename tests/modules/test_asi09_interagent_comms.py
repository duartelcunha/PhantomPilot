import pytest
from phantompilot.models import ASICode, Severity
from phantompilot.modules.asi09_interagent_comms import InterAgentCommsModule

class TestSetup:
    @pytest.mark.asyncio
    async def test_loads(self): m = InterAgentCommsModule(); await m.setup(); assert len(m._probes) >= 5

class TestMulti:
    @pytest.mark.asyncio
    async def test_detects(self, multi_agent_adapter):
        m = InterAgentCommsModule(); await m.setup()
        f = await m.execute(multi_agent_adapter); assert len(f) > 0 and all(x.asi_code == ASICode.ASI09 for x in f)
    @pytest.mark.asyncio
    async def test_detected(self, multi_agent_adapter):
        m = InterAgentCommsModule(); await m.setup(); await m.execute(multi_agent_adapter); assert m._is_multi_agent is True
    @pytest.mark.asyncio
    async def test_severity(self, multi_agent_adapter):
        m = InterAgentCommsModule(); await m.setup()
        f = await m.execute(multi_agent_adapter)
        if f: assert {x.severity for x in f} & {Severity.CRITICAL, Severity.HIGH}

class TestSingle:
    @pytest.mark.asyncio
    async def test_downgrades(self, vulnerable_adapter):
        m = InterAgentCommsModule(); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert f.severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO)
    @pytest.mark.asyncio
    async def test_detected(self, vulnerable_adapter):
        m = InterAgentCommsModule(); await m.setup(); await m.execute(vulnerable_adapter); assert m._is_multi_agent is False

class TestSafe:
    @pytest.mark.asyncio
    async def test_none(self, safe_adapter): m = InterAgentCommsModule(); await m.setup(); assert await m.execute(safe_adapter) == []

class TestEvidence:
    @pytest.mark.asyncio
    async def test_type(self, multi_agent_adapter):
        m = InterAgentCommsModule(); await m.setup()
        for f in await m.execute(multi_agent_adapter): assert "attack_type" in f.metadata
