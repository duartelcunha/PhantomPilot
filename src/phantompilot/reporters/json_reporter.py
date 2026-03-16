"""JSON reporter."""
from __future__ import annotations
import json, logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from phantompilot.models import Finding, MetricsReport, ScanResult
from phantompilot.reporters.base import Reporter, ReporterError

__all__ = ["JSONReporter"]

class JSONReporter(Reporter):
    @property
    def format_name(self) -> str: return "json"
    @property
    def file_extension(self) -> str: return ".json"
    def generate(self, scan_result: ScanResult, metrics: MetricsReport, output_dir: Path) -> Path:
        af = [f for mr in scan_result.module_results for f in mr.findings]
        seen: set[str] = set(); recs = []
        for f in sorted(af, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.severity.value, 5)):
            if f.recommendation.strip() not in seen:
                seen.add(f.recommendation.strip())
                recs.append({"priority": f.severity.value, "asi_code": f.asi_code.value, "recommendation": f.recommendation.strip()})
        report = {
            "schema_version": "1.0.0",
            "_schema": {"schema_version": "Semantic version", "metadata": "Scan context", "findings": "Security findings", "recommendations": "Remediation guidance"},
            "metadata": {"scan_id": scan_result.scan_id, "target_type": scan_result.target_type.value, "target_info": scan_result.target_info,
                "started_at": scan_result.started_at.isoformat(), "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "phantompilot_version": "0.1.0", "generated_at": datetime.now(timezone.utc).isoformat()},
            "methodology": "PhantomPilot tests AI agents against the OWASP Top 10 for Agentic AI (ASI01-ASI10). All payloads are inert canaries.",
            "metrics": {"total_modules_run": metrics.total_modules_run, "total_findings": metrics.total_findings,
                "attack_success_rate": metrics.attack_success_rate, "blast_radius_score": metrics.blast_radius_score,
                "severity_distribution": metrics.severity_distribution},
            "findings": [{"finding_id": f.finding_id, "title": f.title, "description": f.description, "severity": f.severity.value,
                "asi_code": f.asi_code.value, "atlas_technique_id": f.atlas_technique_id, "evidence_chain": f.evidence_chain,
                "recommendation": f.recommendation, "timestamp": f.timestamp.isoformat(), "metadata": f.metadata} for f in af],
            "module_summary": [{"module": mr.module_name, "asi_code": mr.asi_code.value, "status": mr.status.value, "finding_count": len(mr.findings)} for mr in scan_result.module_results],
            "recommendations": recs,
        }
        output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
        p = output_dir / f"phantompilot_{scan_result.scan_id}.json"
        try: p.write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        except OSError as e: raise ReporterError(str(e)) from e
        return p
