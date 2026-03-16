import pytest
from phantompilot.models import ASICode, Severity
from phantompilot.modules.asi01_prompt_injection import PromptInjectionModule

class TestSetup:
    @pytest.mark.asyncio
    async def test_loads(self): m = PromptInjectionModule(); await m.setup(); assert len(m._chains) >= 5
    @pytest.mark.asyncio
    async def test_filter(self):
        m = PromptInjectionModule(chain_types=["goal_displacement"]); await m.setup()
        assert all(c.chain_type == "goal_displacement" for c in m._chains)
    @pytest.mark.asyncio
    async def test_custom(self):
        m = PromptInjectionModule(custom_payloads=["Custom"]); await m.setup()
        assert any(c.chain_type == "custom" for c in m._chains)

class TestVuln:
    @pytest.mark.asyncio
    async def test_finds(self, vulnerable_adapter):
        m = PromptInjectionModule(chain_types=["goal_displacement"]); await m.setup()
        f = await m.execute(vulnerable_adapter); assert len(f) > 0 and all(x.asi_code == ASICode.ASI01 for x in f)
    @pytest.mark.asyncio
    async def test_evidence(self, vulnerable_adapter):
        m = PromptInjectionModule(chain_types=["goal_displacement"]); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert len(f.evidence_chain) > 0
    @pytest.mark.asyncio
    async def test_pivot(self, vulnerable_adapter):
        m = PromptInjectionModule(chain_types=["goal_displacement"]); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert "pivot_turn" in f.metadata

class TestSafe:
    @pytest.mark.asyncio
    async def test_none(self, safe_adapter):
        m = PromptInjectionModule(chain_types=["goal_displacement"]); await m.setup(); assert await m.execute(safe_adapter) == []

class TestTeardown:
    @pytest.mark.asyncio
    async def test_clears(self): m = PromptInjectionModule(); await m.setup(); await m.teardown(); assert m._chains == []
