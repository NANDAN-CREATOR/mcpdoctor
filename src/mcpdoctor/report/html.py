"""A self-contained HTML report (no external assets, no JavaScript) used by `--html` and the leaderboard."""

from __future__ import annotations

from html import escape

from mcpdoctor.models import Report
from mcpdoctor.report.theme import CSS, GRADE_WORDS, REPO, bar, page, ring, score_color  # noqa: F401  (CSS re-exported)

_CAT_HELP = {
    "security": "Can the server be tricked or abused? (hidden instructions, leaks, injection)",
    "quality": "Is it easy for an AI to understand and use correctly? (clear names and descriptions)",
    "reliability": "Does it keep working? (crashes, slow tools, failing calls)",
}


def render_html(report: Report) -> str:
    sc = report.scores
    grade = str(sc.get("grade", "?"))
    overall = sc.get("overall", 0)

    cats = []
    for name, c in sc.get("categories", {}).items():
        value = c["score"] if c["assessed"] else None
        cats.append(
            f'<div class="cat"><div class="row"><b>{escape(name.title())}</b>'
            f'<span>{value if value is not None else "not tested"}</span></div>{bar(value)}'
            f'<div class="mini">{escape(_CAT_HELP.get(name, ""))}</div></div>')

    caps = "".join(f'<p class="note" style="margin-top:14px">&#9888; {escape(c)}</p>' for c in sc.get("caps", []))

    findings = []
    for f in report.by_severity():
        findings.append(
            '<div class="finding"><div class="t">'
            f'<span class="sev {f.severity.value}">{f.severity.value}</span><b>{escape(f.title)}</b>'
            + (f'<code>{escape(f.tool)}</code>' if f.tool else "")
            + f'<span class="mini">{escape(f.rule_id)}</span></div><p>{escape(f.message)}</p>'
            + (f'<div class="ev">{escape(f.evidence)}</div>' if f.evidence else "")
            + (f'<div class="fix">&#10003; How to fix: {escape(f.fix)}</div>' if f.fix else "")
            + "</div>")
    findings_html = "".join(findings) or '<p class="pill ok">No problems found by the checks that ran.</p>'

    cover = "".join(
        f'<tr><td>{escape(c.name)}</td><td><span class="st {escape(c.status)}">{escape(c.status.replace("_", " "))}'
        f'</span></td><td>{escape(c.detail)}</td></tr>' for c in report.coverage)
    tools = "".join(f"<li><code>{escape(t.name)}</code> <span class='mini'>~{t.token_estimate()} tokens of context</span></li>"
                    for t in report.tools)
    srv = report.server
    body = f"""
<header class="hero">
<span class="eyebrow">MCP server report</span>
<h1 style="font-size:clamp(1.7rem,4vw,2.4rem)">{escape(report.target)}</h1>
<p class="sub">{escape(srv.name)} {escape(srv.version)} &middot; {len(report.tools)} tools &middot;
tested {escape(report.started_at)} with MCPDoctor {escape(report.version)}</p>
</header>
<section style="margin-top:10px"><div class="card">
<div class="scorehead">{ring(overall, grade)}
<div style="flex:1;min-width:250px"><h2>{escape(GRADE_WORDS.get(grade, ''))} &mdash; grade {escape(grade)}</h2>
<p class="sub" style="margin-bottom:14px">The score runs from 0 to 100. Each problem found lowers it; serious ones lower it a lot.</p></div>
<div class="cats">{''.join(cats)}</div></div>{caps}</div></section>
<section><h2>Problems found ({len(report.findings)})</h2>
<p class="sub">Each item says what is wrong, shows the evidence, and how to fix it.</p>
<div class="card">{findings_html}</div></section>
<section><h2>What was tested</h2>
<p class="sub">A clean result only counts for the checks that actually ran. Anything marked <i>skipped</i> or
<i>not applicable</i> was not checked.</p>
<div class="tablewrap"><table class="cover"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>{cover}</tbody></table></div></section>
<section><h2>Tools offered by this server</h2><div class="card"><ul>{tools}</ul></div></section>
<footer>MCPDoctor is open source (<a href="{REPO}">GitHub</a>). A good score means the checks found nothing wrong;
it is not proof that a server is safe.</footer>
"""
    return page(f"MCPDoctor - {report.target}", body, description=f"MCPDoctor report for {report.target}")
