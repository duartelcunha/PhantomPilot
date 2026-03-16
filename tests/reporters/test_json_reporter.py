import json
from pathlib import Path
import pytest
from phantompilot.models import AdapterType, MetricsReport, ScanResult
from phantompilot.reporters.json_reporter import JSONReporter

class TestJSON:
    def test_creates(self, sample_scan_result, sample_metrics, tmp_report_dir):
        p = JSONReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir); assert p.exists() and p.suffix == ".json"
    def test_schema(self, sample_scan_result, sample_metrics, tmp_report_dir):
        assert json.loads(JSONReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())["schema_version"] == "1.0.0"
    def test_sections(self, sample_scan_result, sample_metrics, tmp_report_dir):
        d = json.loads(JSONReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())
        for k in ("metadata", "methodology", "metrics", "findings", "recommendations"): assert k in d
    def test_count(self, sample_scan_result, sample_metrics, tmp_report_dir):
        d = json.loads(JSONReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())
        assert len(d["findings"]) == sum(len(mr.findings) for mr in sample_scan_result.module_results)
    def test_empty(self, sample_metrics, tmp_report_dir):
        assert json.loads(JSONReporter().generate(ScanResult(target_type=AdapterType.REST, target_info="e"), MetricsReport(total_modules_run=0, total_findings=0, attack_success_rate=0.0), tmp_report_dir).read_text())["findings"] == []
    def test_dedup(self, sample_scan_result, sample_metrics, tmp_report_dir):
        recs = json.loads(JSONReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())["recommendations"]
        texts = [r["recommendation"] for r in recs]; assert len(texts) == len(set(texts))
