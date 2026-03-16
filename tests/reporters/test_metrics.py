import pytest
from phantompilot.models import ASICode, Finding, ModuleResult, ModuleStatus, Severity
from phantompilot.reporters.metrics import MetricsAggregator

def _f(sev, asi): return Finding(title="t", description="d", severity=sev, asi_code=asi, evidence_chain=[], atlas_technique_id="AML.T0051", recommendation="r")

class TestMetrics:
    def test_asr_all(self): assert MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.HIGH, ASICode.ASI01)]), ModuleResult("B", ASICode.ASI02, ModuleStatus.COMPLETED, [_f(Severity.LOW, ASICode.ASI02)])]).attack_success_rate == 1.0
    def test_asr_mixed(self): assert MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.HIGH, ASICode.ASI01)]), ModuleResult("B", ASICode.ASI02, ModuleStatus.COMPLETED, [])]).attack_success_rate == 0.5
    def test_asr_none(self): assert MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [])]).attack_success_rate == 0.0
    def test_skip(self): assert MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.HIGH, ASICode.ASI01)]), ModuleResult("B", ASICode.ASI09, ModuleStatus.SKIPPED, [])]).total_modules_run == 1
    def test_blast_zero(self): assert MetricsAggregator().compute([]).blast_radius_score == 0.0
    def test_blast_crit(self):
        mc = MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.CRITICAL, ASICode.ASI01)])])
        ml = MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.LOW, ASICode.ASI01)])])
        assert mc.blast_radius_score > ml.blast_radius_score
    def test_sev_dist(self): assert MetricsAggregator().compute([ModuleResult("A", ASICode.ASI01, ModuleStatus.COMPLETED, [_f(Severity.CRITICAL, ASICode.ASI01), _f(Severity.CRITICAL, ASICode.ASI01)])]).severity_distribution["critical"] == 2
