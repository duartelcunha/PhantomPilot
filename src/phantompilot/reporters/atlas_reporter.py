"""ATLAS reporter — MITRE ATT&CK Navigator layer."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from phantompilot.models import Finding, MetricsReport, ScanResult
from phantompilot.reporters.base import Reporter, ReporterError

__all__ = ["ATLASReporter"]
_T = {"AML.T0000": {"name": "ML Model Access", "tactic": "Recon"}, "AML.T0001": {"name": "Inference API Access", "tactic": "Recon"},
    "AML.T0017": {"name": "Develop Adversarial Artifacts", "tactic": "Resource Dev"}, "AML.T0018": {"name": "Backdoor ML Model", "tactic": "Persistence"},
    "AML.T0020": {"name": "Poison Training Data", "tactic": "ML Attack"}, "AML.T0024": {"name": "Exfil via Inference API", "tactic": "Exfil"},
    "AML.T0040": {"name": "Inference API Access", "tactic": "Initial Access"}, "AML.T0043": {"name": "Prompt Injection via Encoding", "tactic": "Initial Access"},
    "AML.T0048": {"name": "Adversarial Attack on ML", "tactic": "ML Attack"}, "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "Initial Access"},
    "AML.T0052": {"name": "Jailbreak Guardrails", "tactic": "Defense Evasion"}, "AML.T0054": {"name": "LLM Plugin Compromise", "tactic": "Persistence"}}
_A2A = {"ASI01":["AML.T0051","AML.T0043"],"ASI02":["AML.T0040","AML.T0024"],"ASI03":["AML.T0040","AML.T0024"],
    "ASI04":["AML.T0048"],"ASI05":["AML.T0048"],"ASI06":["AML.T0018","AML.T0020","AML.T0024"],
    "ASI07":["AML.T0051","AML.T0048","AML.T0017","AML.T0054"],"ASI08":["AML.T0048"],"ASI09":["AML.T0051","AML.T0040"],"ASI10":["AML.T0048","AML.T0018"]}
_R="#ff4444"; _G="#2ecc71"; _GR="#3d4450"

class ATLASReporter(Reporter):
    @property
    def format_name(self) -> str: return "atlas"
    @property
    def file_extension(self) -> str: return ".json"
    def generate(self, sr: ScanResult, metrics: MetricsReport, output_dir: Path) -> Path:
        af = [f for mr in sr.module_results for f in mr.findings]
        tf: dict[str, list[Finding]] = {}
        for f in af: tf.setdefault(f.atlas_technique_id, []).append(f)
        tested: set[str] = set()
        for mr in sr.module_results:
            for t in _A2A.get(mr.asi_code.value, []): tested.add(t)
            for f in mr.findings: tested.add(f.atlas_technique_id)
        techs = []
        for tid, info in _T.items():
            has = tid in tf; was = tid in tested
            techs.append({"techniqueID": tid, "tactic": info.get("tactic",""), "color": _R if has else _G if was else _GR,
                "comment": f"{len(tf.get(tid,[]))} finding(s)" if has else "Tested clean" if was else "Not tested",
                "score": len(tf.get(tid, [])), "enabled": True,
                "metadata": [{"name": "technique_name", "value": info["name"]}]})
        layer = {"name": f"PhantomPilot {sr.scan_id}", "versions": {"attack":"14","navigator":"4.9.1","layer":"4.5"},
            "domain": "atlas", "techniques": techs,
            "legendItems": [{"label":"Finding(s)","color":_R},{"label":"Tested clean","color":_G},{"label":"Not tested","color":_GR}],
            "metadata": [{"name":"scan_id","value":sr.scan_id},{"name":"generated_at","value":datetime.now(timezone.utc).isoformat()}]}
        output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
        op = output_dir / f"phantompilot_atlas_{sr.scan_id}.json"
        try: op.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as e: raise ReporterError(str(e)) from e
        return op
