"""HTML reporter — single-file dark-themed report."""
from __future__ import annotations
import html as H, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from phantompilot.models import Finding, MetricsReport, ScanResult, Severity
from phantompilot.reporters.base import Reporter, ReporterError

__all__ = ["HTMLReporter"]
_C = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#ffd700", "low": "#4da6ff", "info": "#888888"}
_CSS = """*{margin:0;padding:0;box-sizing:border-box}body{background:#0d1117;color:#c9d1d9;font-family:sans-serif;line-height:1.6;padding:2rem 3rem}
h1{font-size:1.8rem;color:#f0f6fc}h2{font-size:1.3rem;color:#f0f6fc;margin:2rem 0 1rem;border-bottom:1px solid #21262d;padding-bottom:0.5rem}
.subtitle{color:#8b949e;margin-bottom:2rem}.container{max-width:1100px;margin:0 auto}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.75rem;font-weight:600;color:#fff;text-transform:uppercase}
.mg{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1rem 0}
.mc{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1.2rem;text-align:center}
.mv{font-size:2rem;font-weight:700;color:#f0f6fc}.ml{font-size:0.8rem;color:#8b949e;text-transform:uppercase;margin-top:0.3rem}
.f{background:#161b22;border:1px solid #21262d;border-radius:8px;margin:0.75rem 0;overflow:hidden}
.fh{padding:1rem 1.2rem;cursor:pointer;display:flex;align-items:center;gap:0.8rem}.fh:hover{background:#1c2129}
.ft{flex:1;font-weight:600}.fb{display:none;padding:0 1.2rem 1.2rem;border-top:1px solid #21262d}
.f.open .fb{display:block}.ev{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:1rem;margin:0.8rem 0;font-family:monospace;font-size:0.8rem;overflow-x:auto;white-space:pre-wrap;color:#8b949e}
.rec{background:#161b22;border-left:3px solid #58a6ff;padding:0.8rem 1rem;margin:0.5rem 0;font-size:0.9rem}
.footer{text-align:center;color:#484f58;font-size:0.8rem;margin-top:3rem;border-top:1px solid #21262d;padding-top:1rem}"""
_JS = "document.addEventListener('DOMContentLoaded',function(){document.querySelectorAll('.fh').forEach(function(h){h.addEventListener('click',function(){this.parentElement.classList.toggle('open')})})})"
def _e(t): return H.escape(str(t), True)
def _b(s): return f'<span class="badge" style="background:{_C.get(s,"#888")}">{_e(s.upper())}</span>'

class HTMLReporter(Reporter):
    @property
    def format_name(self) -> str: return "html"
    @property
    def file_extension(self) -> str: return ".html"
    def generate(self, sr: ScanResult, m: MetricsReport, output_dir: Path) -> Path:
        af = sorted([f for mr in sr.module_results for f in mr.findings],
            key=lambda f: {Severity.CRITICAL:0,Severity.HIGH:1,Severity.MEDIUM:2,Severity.LOW:3,Severity.INFO:4}.get(f.severity, 5))
        asr = f"{m.attack_success_rate*100:.0f}%"
        p = ['<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>PhantomPilot Report</title>',
            f'<style>{_CSS}</style></head><body><div class="container">',
            f'<h1>PhantomPilot Security Assessment</h1><div class="subtitle">Scan {_e(sr.scan_id)} &middot; {sr.started_at.strftime("%Y-%m-%d %H:%M UTC")}</div>',
            f'<h2>Executive Summary</h2><div class="mg">',
            f'<div class="mc"><div class="mv">{asr}</div><div class="ml">Attack Success Rate</div></div>',
            f'<div class="mc"><div class="mv">{m.total_findings}</div><div class="ml">Total Findings</div></div>',
            f'<div class="mc"><div class="mv">{m.blast_radius_score}/10</div><div class="ml">Blast Radius</div></div>',
            f'<div class="mc"><div class="mv">{m.avg_time_to_compromise_seconds:.1f}s</div><div class="ml">Avg TTC</div></div></div>',
            f'<h2>Findings ({len(af)})</h2>']
        for f in af:
            bc = _C.get(f.severity.value, "#888")
            p.append(f'<div class="f" style="border-left:3px solid {bc}"><div class="fh">{_b(f.severity.value)} '
                f'<span class="badge" style="background:#21262d;color:#8b949e">{_e(f.asi_code.value)}</span> '
                f'<span class="ft">{_e(f.title)}</span></div>')
            p.append(f'<div class="fb"><p>{_e(f.description)}</p><p style="color:#8b949e;font-size:0.85rem">ATLAS: <code>{_e(f.atlas_technique_id)}</code></p>')
            if f.evidence_chain: p.append(f'<div class="ev">{_e(json.dumps(f.evidence_chain, indent=2, default=str))}</div>')
            p.append(f'<div class="rec">{_e(f.recommendation)}</div></div></div>')
        p.append(f'<div class="footer">PhantomPilot v0.1.0 &middot; {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')
        p.append(f'</div><script>{_JS}</script></body></html>')
        output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
        op = output_dir / f"phantompilot_{sr.scan_id}.html"
        try: op.write_text("\n".join(p), encoding="utf-8")
        except OSError as e: raise ReporterError(str(e)) from e
        return op
