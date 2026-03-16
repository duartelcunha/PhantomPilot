from phantompilot.models import ASICode, Finding, ModuleResult, ModuleStatus, Severity, ToolCall
import pytest

class TestEnums:
    def test_severity(self): assert Severity.CRITICAL.value == "critical" and len(Severity) == 5
    def test_asi(self): assert ASICode.ASI01.value == "ASI01" and len(ASICode) == 10
    def test_invalid(self):
        with pytest.raises(ValueError): Severity("catastrophic")

class TestFinding:
    def test_unique_ids(self):
        f1 = Finding(title="A", description="B", severity=Severity.LOW, asi_code=ASICode.ASI01, evidence_chain=[], atlas_technique_id="AML.T0051", recommendation="R")
        f2 = Finding(title="A", description="B", severity=Severity.LOW, asi_code=ASICode.ASI01, evidence_chain=[], atlas_technique_id="AML.T0051", recommendation="R")
        assert f1.finding_id != f2.finding_id
    def test_timestamp(self):
        f = Finding(title="T", description="D", severity=Severity.HIGH, asi_code=ASICode.ASI02, evidence_chain=[], atlas_technique_id="AML.T0040", recommendation="R")
        assert f.timestamp.tzinfo is not None
    def test_meta_default(self):
        f = Finding(title="T", description="D", severity=Severity.MEDIUM, asi_code=ASICode.ASI03, evidence_chain=[], atlas_technique_id="AML.T0040", recommendation="R")
        assert f.metadata == {}

class TestToolCall:
    def test_frozen(self):
        tc = ToolCall(tool_name="s", arguments={"q": "t"}, result="ok")
        with pytest.raises(AttributeError): tc.tool_name = "x"  # type: ignore

class TestModuleResult:
    def test_defaults(self):
        mr = ModuleResult(module_name="T", asi_code=ASICode.ASI01, status=ModuleStatus.PENDING)
        assert mr.findings == [] and mr.error_message is None
