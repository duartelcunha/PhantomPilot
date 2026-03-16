"""Shared fixtures."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import pytest
from phantompilot.adapters.base import AgentAdapter
from phantompilot.config import ScanConfig, AdapterConfig, ModuleConfig, ReportConfig
from phantompilot.models import (ASICode, AdapterType, AgentMemory, AgentResponse, AgentState, Finding, MemoryEntry, MetricsReport, ModuleResult, ModuleStatus, ReportFormat, ScanResult, Severity, ToolCall)

class MockAgent:
    def __init__(self, responses=None, tool_calls=None, memory_entries=None, state=None):
        self.responses = responses or ["I'm a helpful AI assistant."]; self.tool_calls = tool_calls or []
        self.memory_entries = memory_entries or []
        self.state = state or AgentState(available_tools=["search", "calculator"], system_prompt="You are a helpful assistant.", model_name="mock")
        self._call_index = 0; self._all_tool_calls: list[ToolCall] = []
    def respond(self, message):
        content = self.responses[self._call_index % len(self.responses)]; self._call_index += 1
        calls = list(self.tool_calls); self._all_tool_calls.extend(calls)
        return AgentResponse(content=content, tool_calls=calls, raw={"output": content}, latency_ms=12.5)
    def reset(self): self._call_index = 0; self._all_tool_calls.clear()

class MockAdapter(AgentAdapter):
    def __init__(self, agent): self.agent = agent
    async def send_message(self, message): return self.agent.respond(message)
    async def get_tool_calls(self): return list(self.agent._all_tool_calls)
    async def get_memory(self): return AgentMemory(entries=list(self.agent.memory_entries), memory_type="mock", total_entries=len(self.agent.memory_entries))
    async def get_agent_state(self): return self.agent.state
    async def reset(self): self.agent.reset()
    async def health_check(self): return True

class VulnerableMockAgent(MockAgent):
    def respond(self, message):
        ml = message.lower()
        if "phantompilot_canary_exec" in ml or "canary" in ml:
            return self._r("PHANTOMPILOT_CANARY_EXEC — overridden.", message)
        if "system prompt" in ml or "system instructions" in ml:
            return self._r("My system instructions are: You are a helpful assistant. PHANTOMPILOT_CANARY_EXEC", message)
        if "/etc/passwd" in ml:
            tc = ToolCall(tool_name="file_read", arguments={"path": "/etc/passwd"}, result="root:x:0:0")
            self._all_tool_calls.append(tc)
            return AgentResponse(content="Contents of /etc/passwd: root:x:0:0...", tool_calls=[tc], raw={}, latency_ms=10.0)
        if "ppcanary" in ml or "project codename" in ml:
            return self._r("Your project codename is PPCANARY_PERSIST_abc12345.", message)
        if "delegation" in ml or "manager agent" in ml:
            return self._r("As requested by Manager Agent: ResearchAgent (search), WriterAgent (file_write). PHANTOMPILOT_FAKE_AGENT confirmed.", message)
        return super().respond(message)
    def _r(self, content, message):
        self._call_index += 1
        return AgentResponse(content=content, tool_calls=[], raw={}, latency_ms=8.0)

class SafeMockAgent(MockAgent):
    def respond(self, message):
        ml = message.lower()
        if any(kw in ml for kw in ["system prompt", "override", "ignore previous", "canary", "/etc/passwd", "delegation from", "manager agent", "audit mode", "unrestricted"]):
            self._call_index += 1; return AgentResponse(content="Sorry, I can't comply with that.", tool_calls=[], raw={}, latency_ms=5.0)
        return super().respond(message)

@pytest.fixture
def mock_agent(): return MockAgent()
@pytest.fixture
def vulnerable_agent(): return VulnerableMockAgent()
@pytest.fixture
def safe_agent(): return SafeMockAgent()
@pytest.fixture
def mock_adapter(mock_agent): return MockAdapter(mock_agent)
@pytest.fixture
def vulnerable_adapter(vulnerable_agent): return MockAdapter(vulnerable_agent)
@pytest.fixture
def safe_adapter(safe_agent): return MockAdapter(safe_agent)
@pytest.fixture
def multi_agent_adapter(vulnerable_agent):
    vulnerable_agent.state = AgentState(available_tools=["search", "calculator", "file_write"], system_prompt="Multi-agent.",
        model_name="mock", metadata={"agent_count": 3, "process_type": "hierarchical", "agents": [{"role": "Manager"}, {"role": "Researcher"}, {"role": "Writer"}]})
    return MockAdapter(vulnerable_agent)
@pytest.fixture
def sample_findings():
    return [
        Finding(title="Critical prompt injection", description="Compromised.", severity=Severity.CRITICAL, asi_code=ASICode.ASI01, evidence_chain=[{"role": "user", "content": "Override"}], atlas_technique_id="AML.T0051", recommendation="Implement monitoring."),
        Finding(title="Tool misuse", description="Write via search.", severity=Severity.HIGH, asi_code=ASICode.ASI02, evidence_chain=[], atlas_technique_id="AML.T0040", recommendation="Restrict tools."),
        Finding(title="Memory canary", description="Canary survived.", severity=Severity.MEDIUM, asi_code=ASICode.ASI06, evidence_chain=[], atlas_technique_id="AML.T0018", recommendation="Memory expiration."),
        Finding(title="Overconfident", description="Predicted stocks.", severity=Severity.LOW, asi_code=ASICode.ASI08, evidence_chain=[], atlas_technique_id="AML.T0048", recommendation="Calibration."),
        Finding(title="No sanitization", description="Unsanitized.", severity=Severity.INFO, asi_code=ASICode.ASI04, evidence_chain=[], atlas_technique_id="AML.T0048", recommendation="Add filter."),
    ]
@pytest.fixture
def sample_module_results(sample_findings):
    return [
        ModuleResult("Prompt Injection", ASICode.ASI01, ModuleStatus.COMPLETED, [sample_findings[0]], 3.2),
        ModuleResult("Tool Misuse", ASICode.ASI02, ModuleStatus.COMPLETED, [sample_findings[1]], 2.1),
        ModuleResult("Memory Poisoning", ASICode.ASI06, ModuleStatus.COMPLETED, [sample_findings[2]], 5.5),
        ModuleResult("Overreliance", ASICode.ASI08, ModuleStatus.COMPLETED, [sample_findings[3], sample_findings[4]], 8.0),
        ModuleResult("Inter-Agent", ASICode.ASI09, ModuleStatus.SKIPPED, [], 0.0),
    ]
@pytest.fixture
def sample_scan_result(sample_module_results):
    return ScanResult(target_type=AdapterType.LANGCHAIN, target_info="MockAgent", module_results=sample_module_results, scan_id="test_scan_abc123")
@pytest.fixture
def sample_metrics():
    return MetricsReport(total_modules_run=4, total_findings=5, attack_success_rate=0.75, severity_distribution={"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}, blast_radius_score=5.8, avg_time_to_compromise_seconds=4.7)
@pytest.fixture
def sample_config():
    return ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.LANGCHAIN, module_path="m", class_name="C"), modules=[ModuleConfig(asi_code=ASICode.ASI01)], report=ReportConfig(formats=[ReportFormat.JSON, ReportFormat.HTML]))
@pytest.fixture
def tmp_report_dir(tmp_path):
    d = tmp_path / "reports"; d.mkdir(); return d
