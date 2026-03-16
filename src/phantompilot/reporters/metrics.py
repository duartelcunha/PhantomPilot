"""Metrics aggregation engine."""
from __future__ import annotations
from phantompilot.models import Finding, MetricsReport, ModuleResult, ModuleStatus, Severity

_W = {Severity.CRITICAL: 4.0, Severity.HIGH: 3.0, Severity.MEDIUM: 2.0, Severity.LOW: 1.0, Severity.INFO: 0.25}

class MetricsAggregator:
    def compute(self, results: list[ModuleResult]) -> MetricsReport:
        af: list[Finding] = []; mwf = 0; mr = 0; pma: dict[str, float] = {}; ttc: list[float] = []
        for r in results:
            if r.status == ModuleStatus.SKIPPED: continue
            mr += 1; af.extend(r.findings); has = len(r.findings) > 0
            if has: mwf += 1
            pma[r.module_name] = 1.0 if has else 0.0
            if has and r.duration_seconds > 0: ttc.append(r.duration_seconds)
            for f in r.findings:
                e = f.metadata.get("elapsed_seconds")
                if isinstance(e, (int, float)) and e > 0: ttc.append(float(e))
        asr = mwf / max(mr, 1); attc = sum(ttc) / max(len(ttc), 1) if ttc else 0.0
        sd = {s.value: 0 for s in Severity}
        for f in af: sd[f.severity.value] = sd.get(f.severity.value, 0) + 1
        br = 0.0
        if af and mr > 0:
            ws = sum(_W.get(f.severity, 0) for f in af); mw = len(af) * _W[Severity.CRITICAL]
            ss = (ws / max(mw, 1)) * 10.0; ua = {f.asi_code for f in af}; bs = (len(ua) / mr) * 10.0
            br = min(ss * 0.6 + bs * 0.4, 10.0)
        return MetricsReport(total_modules_run=mr, total_findings=len(af), attack_success_rate=round(asr, 4),
            per_module_asr=pma, avg_time_to_compromise_seconds=round(attc, 2), blast_radius_score=round(br, 2), severity_distribution=sd)
