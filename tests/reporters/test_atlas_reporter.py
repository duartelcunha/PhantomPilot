import json
from pathlib import Path
import pytest
from phantompilot.reporters.atlas_reporter import ATLASReporter

class TestATLAS:
    def test_creates(self, sample_scan_result, sample_metrics, tmp_report_dir):
        p = ATLASReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir); assert p.exists() and "atlas" in p.name
    def test_structure(self, sample_scan_result, sample_metrics, tmp_report_dir):
        d = json.loads(ATLASReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())
        assert "techniques" in d and "versions" in d and "legendItems" in d
    def test_fields(self, sample_scan_result, sample_metrics, tmp_report_dir):
        for t in json.loads(ATLASReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())["techniques"]:
            assert all(k in t for k in ("techniqueID", "color", "comment")) and t["techniqueID"].startswith("AML.T")
    def test_colors(self, sample_scan_result, sample_metrics, tmp_report_dir):
        colors = {t["color"] for t in json.loads(ATLASReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())["techniques"]}
        assert "#ff4444" in colors and "#3d4450" in colors
    def test_ids(self, sample_scan_result, sample_metrics, tmp_report_dir):
        for t in json.loads(ATLASReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text())["techniques"]:
            n = t["techniqueID"].split("AML.T")[1]; assert n.isdigit() and len(n) == 4
