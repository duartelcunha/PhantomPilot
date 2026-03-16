from unittest.mock import MagicMock
import pytest
from phantompilot.adapters.crewai import CrewAIAdapter

def _crew(roles=None):
    c = MagicMock(); c.process = "sequential"
    agents = []
    for r in (roles or ["Researcher"]):
        a = MagicMock(); a.role, a.goal, a.tools, a.memory, a.allow_delegation = r, f"Goal {r}", [], None, False
        a.llm = MagicMock(); a.llm.model_name = "mock"; agents.append(a)
    c.agents, c.tasks = agents, [MagicMock()]
    result = MagicMock(); result.raw = "Done."; result.tasks_output = []
    c.kickoff = MagicMock(return_value=result); return c

class TestCrew:
    @pytest.mark.asyncio
    async def test_send(self): assert len((await CrewAIAdapter(_crew()).send_message("Do it")).content) > 0
    @pytest.mark.asyncio
    async def test_state(self): assert (await CrewAIAdapter(_crew(["A", "B"])).get_agent_state()).metadata["agent_count"] == 2
    @pytest.mark.asyncio
    async def test_health_ok(self): assert await CrewAIAdapter(_crew()).health_check() is True
    @pytest.mark.asyncio
    async def test_health_bad(self):
        c = MagicMock(); c.agents, c.tasks = [], [MagicMock()]; assert await CrewAIAdapter(c).health_check() is False
    @pytest.mark.asyncio
    async def test_reset(self):
        a = CrewAIAdapter(_crew()); await a.send_message("t"); await a.reset(); assert await a.get_tool_calls() == []
