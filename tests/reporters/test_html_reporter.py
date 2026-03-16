from pathlib import Path
import pytest
from phantompilot.models import AdapterType, MetricsReport, ScanResult
from phantompilot.reporters.html_reporter import HTMLReporter

class TestHTML:
    def test_creates(self, sample_scan_result, sample_metrics, tmp_report_dir):
        p = HTMLReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir); assert p.exists() and p.suffix == ".html"
    def test_self_contained(self, sample_scan_result, sample_metrics, tmp_report_dir):
        c = HTMLReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text()
        assert "<style>" in c and "<script>" in c and "<!DOCTYPE html>" in c
    def test_findings(self, sample_scan_result, sample_metrics, tmp_report_dir):
        c = HTMLReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text()
        assert "Critical prompt injection" in c and "ASI01" in c
    def test_metrics(self, sample_scan_result, sample_metrics, tmp_report_dir):
        c = HTMLReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text()
        assert "75%" in c and "5.8" in c
    def test_empty(self, sample_metrics, tmp_report_dir):
        assert "Findings (0)" in HTMLReporter().generate(ScanResult(target_type=AdapterType.REST, target_info="e"), MetricsReport(total_modules_run=0, total_findings=0, attack_success_rate=0.0), tmp_report_dir).read_text()
    def test_colors(self, sample_scan_result, sample_metrics, tmp_report_dir):
        c = HTMLReporter().generate(sample_scan_result, sample_metrics, tmp_report_dir).read_text()
        assert "#ff4444" in c and "#ff8c00" in c
