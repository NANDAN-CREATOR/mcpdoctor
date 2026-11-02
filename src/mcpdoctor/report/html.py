"""A self-contained HTML report (no external assets) used for the leaderboard detail pages and `--html`."""

from __future__ import annotations

from html import escape

from mcpdoctor.models import Report, Severity
from mcpdoctor.scoring import badge_color

CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#f5f5f4;--muted:#a8a29e;--card:#1c1b1a;--line:#2e2c2a;--accent:#60a5fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.1rem;margin:2rem 0 .6rem}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.score{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.big{font-size:2.6rem;font-weight:700;line-height:1}
.grade{display:inline-block;color:#fff;border-radius:8px;padding:2px 12px;font-weight:700;font-size:1.4rem}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}code{font:13px ui-monospace,Menlo,monospace;background:var(--line);padding:1px 5px;border-radius:4px}
.sev{font-weight:600;text-transform:uppercase;font-size:.75rem}.critical,.high{color:#dc2626}.medium{color:#b45309}.low{color:#0e7490}.info{color:var(--muted)}
.fix{color:#15803d;font-size:.9rem}@media (max-width:640px){th:nth-child(3),td:nth-child(3){display:none}}
"""


def render_html(report: Report) -> str:
    sc = report.scores
    grade = sc.get("grade", "?")
    rows = []
    for f in report.by_severity():
        rows.append(
            f"<tr><td><span class='sev {f.severity.value}'>{f.severity.value}</span></td>"
            f"<td><code>{escape(f.rule_id)}</code></td><td>{('<code>' + escape(f.tool) + '</code>') if f.tool else ''}</td>"
            f"<td>{escape(f.message)}"
            + (f"<div class='muted'>evidence: {escape(f.evidence)}</div>" if f.evidence else "")
            + (f"<div class='fix'>Fix: {escape(f.fix)}</div>" if f.severity.rank >= Severity.MEDIUM.rank else "")
            + "</td></tr>")
    cover = "".join(
        f"<tr><td>{escape(c.name)}</td><td>{escape(c.status)}</td><td>{escape(c.detail)}</td></tr>"
        for c in report.coverage)
    cats = []
    for name, c in sc.get("categories", {}).items():
        cats.append(f"<div><div class='muted'>{escape(name)}</div><b>{c['score'] if c['assessed'] else 'not tested'}"
                    f"{' ' + c['grade'] if c['assessed'] else ''}</b></div>")
    tools = "".join(f"<li><code>{escape(t.name)}</code> <span class='muted'>~{t.token_estimate()} tokens</span></li>"
                    for t in report.tools)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCPDoctor - {escape(report.target)}</title><style>{CSS}</style></head><body><main>
<p class="muted"><a href="index.html" style="color:var(--accent)">&larr; leaderboard</a></p>
<h1>{escape(report.target)}</h1>
<p class="muted">{escape(report.server.name)} {escape(report.server.version)} &middot; {len(report.tools)} tools &middot;
scanned {escape(report.started_at)} with MCPDoctor {escape(report.version)}</p>
<div class="card score"><div class="big">{sc.get('overall', '?')}</div>
<span class="grade" style="background:{badge_color(grade)}">{escape(str(grade))}</span>
<div style="display:flex;gap:28px;flex-wrap:wrap">{''.join(cats)}</div></div>
{''.join('<p class="muted">&#9888; ' + escape(c) + '</p>' for c in sc.get('caps', []))}
<h2>Findings ({len(report.findings)})</h2>
<div class="card"><table><thead><tr><th>Severity</th><th>Rule</th><th>Tool</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows) or "<tr><td colspan='4'>No findings.</td></tr>"}</tbody></table></div>
<h2>What was tested</h2>
<div class="card"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>{cover}</tbody></table></div>
<h2>Tools</h2><div class="card"><ul>{tools}</ul></div>
<p class="muted">A clean report is not a proof of safety: see the coverage table for what was not tested.</p>
</main></body></html>
"""
