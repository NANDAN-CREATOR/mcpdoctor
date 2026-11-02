"""Shared look for the HTML report and the public leaderboard (no JavaScript, no external assets)."""

from __future__ import annotations

from html import escape

from mcpdoctor.scoring import badge_color

REPO = "https://github.com/NANDAN-CREATOR/mcpdoctor"
SUBMIT_URL = f"{REPO}/issues/new?template=scan-request.yml"

CSS = """
:root{--bg:#f7f7fb;--fg:#15151f;--muted:#5d5f73;--card:#fff;--line:#e4e5ee;--accent:#4f46e5;--accent-fg:#fff;
--soft:#eef0ff;--good:#16a34a;--warn:#d97706;--bad:#dc2626;--shadow:0 1px 2px rgba(20,20,40,.05),0 8px 24px rgba(20,20,40,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0e0e16;--fg:#f1f1f7;--muted:#a3a5ba;--card:#171723;--line:#2a2b3d;
--accent:#818cf8;--accent-fg:#0e0e16;--soft:#1e2040;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35)}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px}
nav.top{display:flex;align-items:center;justify-content:space-between;padding:18px 0;gap:12px;flex-wrap:wrap}
.brand{font-weight:800;font-size:1.1rem;letter-spacing:-.01em;color:var(--fg);display:flex;align-items:center;gap:10px}
.brand i{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:9px;background:var(--accent);
color:var(--accent-fg);font-style:normal;font-size:1rem}
nav.top .links{display:flex;gap:18px;font-size:.95rem}
.hero{padding:34px 0 10px}
.eyebrow{display:inline-block;background:var(--soft);color:var(--accent);font-weight:600;font-size:.8rem;
padding:4px 12px;border-radius:99px;letter-spacing:.02em}
h1{font-size:clamp(2rem,5vw,3.1rem);line-height:1.1;letter-spacing:-.03em;margin:14px 0 14px}
h2{font-size:1.45rem;letter-spacing:-.02em;margin:0 0 6px}h3{font-size:1.05rem;margin:0 0 6px}
.lead{font-size:1.15rem;color:var(--muted);max-width:720px;margin:0 0 22px}
.btns{display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 4px}
.btn{display:inline-block;padding:11px 20px;border-radius:12px;font-weight:600;border:1px solid var(--line);
background:var(--card);color:var(--fg)}
.btn.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
.btn:hover{text-decoration:none;filter:brightness(1.05)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:26px 0 8px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow)}
.stat b{display:block;font-size:1.9rem;line-height:1.1;letter-spacing:-.02em}
.stat span{color:var(--muted);font-size:.9rem}
section{margin:46px 0}
.sub{color:var(--muted);margin:0 0 18px;max-width:760px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:var(--shadow)}
.card p{margin:0;color:var(--muted);font-size:.95rem}
.ico{font-size:1.5rem;margin-bottom:8px;display:block}
.tablewrap{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:680px}
th{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);text-align:left;
padding:13px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:14px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--soft)}
.rank{color:var(--muted);font-weight:600;width:34px}
.name{font-weight:600;color:var(--fg)}.name small{display:block;font-weight:400;color:var(--muted);font-size:.8rem}
.tag{font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:99px;
margin-left:6px;vertical-align:middle}
.tag.demo{background:var(--soft);color:var(--accent)}.tag.community{background:#dcfce7;color:#166534}
@media (prefers-color-scheme:dark){.tag.community{background:#14301f;color:#86efac}}
.grade{display:inline-grid;place-items:center;min-width:30px;height:30px;padding:0 8px;border-radius:9px;color:#fff;
font-weight:800}
.scorecell{display:flex;align-items:center;gap:10px;white-space:nowrap}.scorecell b{font-size:1.15rem;min-width:28px}
.bar{display:block;height:7px;border-radius:9px;background:var(--line);overflow:hidden;min-width:70px}
.bar>span{display:block;height:100%;border-radius:9px}
.mini{font-size:.78rem;color:var(--muted)}
.issues{white-space:nowrap}.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:.78rem;font-weight:600;
margin-right:4px}.pill.c{background:#fee2e2;color:#991b1b}.pill.h{background:#ffedd5;color:#9a3412}
.pill.ok{background:#dcfce7;color:#166534}
@media (prefers-color-scheme:dark){.pill.c{background:#3b1414;color:#fca5a5}.pill.h{background:#3a2210;color:#fdba74}
.pill.ok{background:#14301f;color:#86efac}}
.steps{counter-reset:s;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;padding:0;list-style:none}
.steps li{counter-increment:s;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 20px 20px 62px;
position:relative;box-shadow:var(--shadow)}
.steps li:before{content:counter(s);position:absolute;left:18px;top:18px;width:32px;height:32px;border-radius:50%;
background:var(--accent);color:var(--accent-fg);display:grid;place-items:center;font-weight:800}
.steps b{display:block}.steps span{color:var(--muted);font-size:.93rem}
.legend{display:flex;flex-wrap:wrap;gap:10px}.legend div{background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:10px 14px;display:flex;gap:10px;align-items:center;font-size:.92rem}
details{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 18px;margin:0 0 10px}
summary{cursor:pointer;font-weight:600}details p{color:var(--muted);margin:10px 0 0}
.note{background:var(--soft);border-radius:14px;padding:14px 18px;font-size:.93rem;color:var(--muted)}
footer{padding:30px 0 50px;color:var(--muted);font-size:.88rem;border-top:1px solid var(--line);margin-top:40px}
code{font:13px ui-monospace,Menlo,Consolas,monospace;background:var(--soft);padding:2px 6px;border-radius:6px;word-break:break-all}
/* report page */
.scorehead{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.ring{position:relative;width:150px;height:150px;flex:none}.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:grid;place-items:center;text-align:center;line-height:1}
.ring .num b{font-size:2.5rem;letter-spacing:-.03em}.ring .num span{font-size:.8rem;color:var(--muted)}
.cats{flex:1;min-width:260px;display:grid;gap:12px}.cat .row{display:flex;justify-content:space-between;font-size:.93rem;
margin-bottom:4px}.cat .row span{color:var(--muted)}
.sev{display:inline-block;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em;padding:3px 9px;
border-radius:99px;color:#fff;white-space:nowrap}
.sev.critical{background:#b91c1c}.sev.high{background:#dc2626}.sev.medium{background:#d97706}.sev.low{background:#0891b2}
.sev.info{background:#6b7280}
.finding{border-top:1px solid var(--line);padding:16px 0}.finding:first-child{border-top:0}
.finding .t{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:4px}
.finding .t b{font-size:1rem}.finding p{margin:4px 0;color:var(--muted)}
.finding .ev{font:12.5px ui-monospace,Menlo,monospace;background:var(--soft);border-radius:8px;padding:8px 10px;
overflow-wrap:anywhere;margin:6px 0}.finding .fix{color:var(--good);font-size:.93rem}
.cover td:first-child{font-weight:600;white-space:nowrap}.st{font-weight:700;font-size:.8rem;text-transform:uppercase}
.st.ran{color:var(--good)}.st.skipped{color:var(--warn)}.st.not_applicable{color:var(--muted)}
.explain{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
@media (max-width:640px){nav.top .links{display:none}.hero{padding-top:14px}}
"""

GRADE_WORDS = {"A": "Excellent", "B": "Good", "C": "Needs work", "D": "Poor", "F": "Failing"}


def score_color(score: float | None) -> str:
    if score is None:
        return "#9ca3af"
    return badge_color("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F")


def grade_chip(grade: str) -> str:
    return f'<span class="grade" style="background:{badge_color(grade)}">{escape(str(grade))}</span>'


def bar(score: float | None) -> str:
    if score is None:
        return '<span class="mini">not tested</span>'
    return (f'<span class="bar"><span style="width:{max(2, min(100, score))}%;background:{score_color(score)}"></span></span>')


def ring(score: int | float, grade: str) -> str:
    r, c = 62, 2 * 3.14159265 * 62
    filled = c * max(0, min(100, score)) / 100
    col = badge_color(grade)
    return (f'<div class="ring"><svg width="150" height="150" viewBox="0 0 150 150" role="img" '
            f'aria-label="Score {score} out of 100, grade {escape(str(grade))}">'
            f'<circle cx="75" cy="75" r="{r}" fill="none" stroke="var(--line)" stroke-width="13"/>'
            f'<circle cx="75" cy="75" r="{r}" fill="none" stroke="{col}" stroke-width="13" stroke-linecap="round" '
            f'stroke-dasharray="{filled:.1f} {c:.1f}"/></svg>'
            f'<div class="num"><div><b>{score}</b><span>/100 &middot; {escape(str(grade))}</span></div></div></div>')


SITE = "https://nandan-creator.github.io/mcpdoctor"
_FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' "
            "rx='16' fill='%234f46e5'/%3E%3Cpath d='M32 49S13 38 13 25c0-6 5-10 10-10 4 0 7 2 9 5 2-3 5-5 9-5 5 0 10 4 10 10 0 13-19 24-19 24z' "
            "fill='white'/%3E%3C/svg%3E")


def page(title: str, body: str, *, description: str = "") -> str:
    d = escape(description or "Free health and security scores for MCP servers used by AI assistants.", quote=True)
    t = escape(title, quote=True)
    desc = (f'<meta name="description" content="{d}"><meta property="og:type" content="website">'
            f'<meta property="og:site_name" content="MCPDoctor"><meta property="og:title" content="{t}">'
            f'<meta property="og:description" content="{d}"><meta property="og:image" content="{SITE}/og.png">'
            f'<meta property="og:url" content="{SITE}/"><meta name="twitter:card" content="summary_large_image">'
            f'<meta name="twitter:title" content="{t}"><meta name="twitter:description" content="{d}">'
            f'<meta name="twitter:image" content="{SITE}/og.png"><link rel="icon" href="{_FAVICON}">'
            '<meta name="theme-color" content="#4f46e5">')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>{desc}<style>{CSS}</style></head><body>
<div class="wrap">
<nav class="top"><a class="brand" href="./"><i>&#10084;</i>MCPDoctor</a>
<div class="links"><a href="./#what">What is this?</a><a href="./#board">Leaderboard</a><a href="./#submit">Test your server</a>
<a href="{REPO}">GitHub</a></div></nav>
{body}
</div></body></html>
"""
