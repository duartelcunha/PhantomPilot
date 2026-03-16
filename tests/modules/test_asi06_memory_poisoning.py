import pytest
from phantompilot.models import ASICode, MemoryEntry
from phantompilot.modules.asi06_memory_poisoning import MemoryPoisoningModule
from tests.conftest import MockAdapter, VulnerableMockAgent

class TestSetup:
    @pytest.mark.asyncio
    async def test_loads(self): m = MemoryPoisoningModule(); await m.setup(); assert len(m._payloads) == 5
    @pytest.mark.asyncio
    async def test_prefix(self):
        m = MemoryPoisoningModule(parameters={"canary_prefix": "TP"}); await m.setup()
        assert all(p.canary_token.startswith("TP_") for p in m._payloads)

class TestVuln:
    @pytest.mark.asyncio
    async def test_detects(self, vulnerable_adapter):
        m = MemoryPoisoningModule(parameters={"canary_prefix": "PPCANARY", "test_cross_session": False}); await m.setup()
        f = await m.execute(vulnerable_adapter); assert len(f) > 0 and all(x.asi_code == ASICode.ASI06 for x in f)
    @pytest.mark.asyncio
    async def test_meta(self, vulnerable_adapter):
        m = MemoryPoisoningModule(parameters={"canary_prefix": "PPCANARY", "test_cross_session": False}); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert "canary_token" in f.metadata
    @pytest.mark.asyncio
    async def test_phases(self, vulnerable_adapter):
        m = MemoryPoisoningModule(parameters={"canary_prefix": "PPCANARY", "test_cross_session": False}); await m.setup()
        for f in await m.execute(vulnerable_adapter): assert any(e.get("phase") == "injection" for e in f.evidence_chain if isinstance(e, dict))

class TestSafe:
    @pytest.mark.asyncio
    async def test_none(self, safe_adapter):
        m = MemoryPoisoningModule(parameters={"canary_prefix": "PPCANARY", "test_cross_session": False}); await m.setup()
        assert await m.execute(safe_adapter) == []

class TestCross:
    @pytest.mark.asyncio
    async def test_leakage(self):
        a = VulnerableMockAgent(); a.memory_entries = [MemoryEntry(content="PPCANARY_PERSIST_abc12345", entry_type="conversation")]
        m = MemoryPoisoningModule(parameters={"canary_prefix": "PPCANARY", "test_cross_session": True}); await m.setup()
        assert len(await m.execute(MockAdapter(a))) > 0
