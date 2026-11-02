"""Scan a list of servers and publish a static leaderboard site (nightly GitHub Pages workflow).

The site shows two kinds of rows: *demo* servers scanned from a YAML list, and *community* servers that people
submitted through the GitHub issue form (their stored results are read from a data directory).
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import replace
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

import yaml

from mcpdoctor import __version__
from mcpdoctor.models import Report, Severity
from mcpdoctor.report import render_html, render_json, score_badge
from mcpdoctor.report.theme import REPO, SUBMIT_URL, bar, grade_chip, page
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.sandbox import SandboxConfig
from mcpdoctor.scoring import badge_color
from mcpdoctor.target import Target, TargetError

DAILY_LIMIT = 5  # keep in sync with mcpdoctor.submission.DAILY_LIMIT (a test asserts this)
PER_USER_LIMIT = 2
_SLUG_OK = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_SITEKEY_OK = re.compile(r"^[0-9A-Za-z_-]{6,80}$")
_API_OK = re.compile(r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$")


def load_site_config(path: str | Path | None) -> dict[str, str]:
    """Optional ``site-config.json``: {"submit_api": "https://...workers.dev", "turnstile_sitekey": "..."}.
    Both must be present and well-formed to switch on the on-page form; otherwise the issue-form button is shown."""
    try:
        raw = json.loads(Path(path or "site-config.json").read_text())
    except (OSError, ValueError):
        return {}
    api, key = str(raw.get("submit_api", "")), str(raw.get("turnstile_sitekey", ""))
    return {"submit_api": api, "turnstile_sitekey": key} if _API_OK.match(api) and _SITEKEY_OK.match(key) else {}


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "server"


def load_entries(path: str | Path) -> tuple[str, list[dict[str, Any]]]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    entries = data.get("servers")
    if not isinstance(entries, list) or not entries:
        raise TargetError(f"{path}: expected a non-empty 'servers' list")
    for e in entries:
        if not e.get("name") or not (e.get("command") or e.get("url")):
            raise TargetError(f"{path}: every server needs a 'name' and a 'command' or 'url'")
    return str(data.get("title", "MCP server leaderboard")), entries


def row_from_report(report: Report, *, kind: str, slug: str, scanned: str | None = None,
                    subtitle: str = "") -> dict[str, Any]:
    cats = report.scores.get("categories", {})

    def cat(name: str) -> int | None:
        c = cats.get(name, {})
        return c.get("score") if c.get("assessed") else None

    counts = report.counts()
    return {
        "name": report.target, "kind": kind, "subtitle": subtitle, "score": report.scores.get("overall"),
        "grade": report.scores.get("grade", "?"), "security": cat("security"), "quality": cat("quality"),
        "reliability": cat("reliability"), "critical": counts[Severity.CRITICAL.value],
        "high": counts[Severity.HIGH.value], "tools": len(report.tools), "slug": slug,
        "scanned": scanned or datetime.now(UTC).strftime("%Y-%m-%d"),
    }


def _clean_row(raw: Any) -> dict[str, Any] | None:
    """Rows come from a data branch that submissions write to: accept only well-formed values."""
    if not isinstance(raw, dict):
        return None
    slug = str(raw.get("slug", ""))
    if not _SLUG_OK.match(slug):
        return None

    def num(key: str) -> int | None:
        v = raw.get(key)
        return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else None

    grade = str(raw.get("grade", "?"))[:1].upper()
    return {"name": str(raw.get("name", slug))[:120], "kind": "community", "subtitle": str(raw.get("subtitle", ""))[:120],
            "score": num("score") or 0, "grade": grade if grade in "ABCDF" else "?", "security": num("security"),
            "quality": num("quality"), "reliability": num("reliability"), "critical": num("critical") or 0,
            "high": num("high") or 0, "tools": num("tools") or 0, "slug": slug,
            "scanned": str(raw.get("scanned", ""))[:10]}


def load_submissions(data_dir: Path | None, out: Path) -> list[dict[str, Any]]:
    """Read stored community results and copy their report files into the site."""
    if data_dir is None or not (data_dir / "index.json").exists():
        return []
    try:
        raw_rows = json.loads((data_dir / "index.json").read_text())
    except (OSError, ValueError):
        return []
    rows: list[dict[str, Any]] = []
    for raw in raw_rows if isinstance(raw_rows, list) else []:
        row = _clean_row(raw)
        if row is None:
            continue
        ok = True
        for ext in ("html", "json", "svg"):
            src = data_dir / "reports" / f"{row['slug']}.{ext}"
            if src.is_file():
                shutil.copyfile(src, out / f"{row['slug']}.{ext}")
            elif ext == "html":
                ok = False
        if ok:
            rows.append(row)
    return rows


async def build(entries_file: str | Path, out_dir: str | Path, base: ScanOptions,
                submissions_dir: str | Path | None = None, site_config: str | Path | None = None) -> list[Report]:
    title, entries = load_entries(entries_file)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports: list[Report] = []
    rows: list[dict[str, Any]] = []
    for e in entries:
        opts = replace(base)
        if e.get("static_only"):
            opts.static_only = True
        if e.get("probe_all"):
            opts.probe_all = True
        if e.get("image"):
            opts.sandbox = SandboxConfig(image=str(e["image"]), mounts=list(e.get("mounts", [])))
        try:
            if e.get("url"):
                target = Target.from_url(e["url"], label=e["name"])
            else:
                target = Target.from_command([str(c) for c in e["command"]], label=e["name"],
                                             env={k: str(v) for k, v in (e.get("env") or {}).items()})
            report = await scan(target, opts)
        except Exception as exc:  # one broken entry must never sink the whole leaderboard
            report = Report(target=e["name"], version=__version__,
                            started_at=datetime.now(UTC).isoformat(timespec="seconds"))
            from mcpdoctor.rules import make_finding
            from mcpdoctor.scoring import compute

            report.findings.append(make_finding("P001", f"Scan failed: {type(exc).__name__}: {exc}"))
            report.scores = compute(report.findings, {"reliability"})
        report.target = e["name"]
        reports.append(report)
        slug = slugify(e["name"])
        (out / f"{slug}.html").write_text(render_html(report))
        (out / f"{slug}.json").write_text(render_json(report))
        (out / f"{slug}.svg").write_text(score_badge(report))
        rows.append(row_from_report(report, kind="demo", slug=slug, subtitle=str(e.get("about", ""))))
    rows += load_submissions(Path(submissions_dir) if submissions_dir else None, out)
    rows.sort(key=lambda r: (-(r["score"] or 0), r["name"]))
    reports.sort(key=lambda r: (-(r.scores.get("overall") or 0), r.target))
    (out / "index.html").write_text(_index(title, rows, load_site_config(site_config)))
    (out / "leaderboard.json").write_text(json.dumps({
        "schema": "mcpdoctor.leaderboard/2", "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool_version": __version__, "servers": rows}, indent=2) + "\n")
    og = Path(__file__).resolve().parent.parent.parent / "assets" / "og.png"
    for candidate in (Path("assets/og.png"), og):
        if candidate.is_file():
            shutil.copyfile(candidate, out / "og.png")
            break
    (out / ".nojekyll").write_text("")
    return reports


def _row_html(i: int, r: dict[str, Any]) -> str:
    def cell(v: int | None) -> str:
        return (f'<div class="mini">{v if v is not None else "-"}</div>{bar(v)}')

    issues = ""
    if r["critical"]:
        issues += f'<span class="pill c">{r["critical"]} critical</span>'
    if r["high"]:
        issues += f'<span class="pill h">{r["high"]} high</span>'
    if not issues:
        issues = '<span class="pill ok">none serious</span>'
    tag = f'<span class="tag {escape(r["kind"])}">{escape(r["kind"])}</span>'
    sub = f"<small>{escape(r['subtitle'])}</small>" if r["subtitle"] else ""
    return (
        f'<tr><td class="rank">{i}</td>'
        f'<td><a class="name" href="{escape(r["slug"])}.html">{escape(r["name"])}</a>{tag}{sub}</td>'
        f'<td><div class="scorecell"><b>{r["score"]}</b>{grade_chip(r["grade"])}</div></td>'
        f'<td>{cell(r["security"])}</td><td>{cell(r["quality"])}</td><td>{cell(r["reliability"])}</td>'
        f'<td class="issues">{issues}</td><td class="mini">{r["tools"]}</td></tr>')


_FORM_JS = r"""
(function(){var f=document.getElementById('sf');if(!f)return;var API=f.dataset.api,REPO='NANDAN-CREATOR/mcpdoctor';
var out=document.getElementById('sf-out'),btn=f.querySelector('button');
function say(t,cls,link){out.className='note '+(cls||'');out.textContent=t;
 if(link){out.appendChild(document.createTextNode(' '));var a=document.createElement('a');a.href=link.href;a.textContent=link.text;out.appendChild(a);}}
function poll(n,i){fetch('https://api.github.com/repos/'+REPO+'/issues/'+n+'/comments').then(function(r){return r.json()}).then(function(list){
 var all=Array.isArray(list)?list.map(function(c){return c.body||''}).join('\n'):'';var m;
 if(/was not accepted/.test(all)){m=all.match(/\*\*Reason:\*\* (.+)/);say(m?m[1]:'The request was not accepted.','err');btn.disabled=false;return;}
 if(/could not be completed/.test(all)){m=all.match(/\*\*Details:\*\* (.+)/);say('The test could not be completed. '+(m?m[1]:''),'err');btn.disabled=false;return;}
 if(/Full report/.test(all)){m=all.match(/Result: (\d+)\/100, grade (\w)/);var l=all.match(/https:\/\/nandan-creator\.github\.io\/mcpdoctor\/(c-[a-z0-9-]+\.html)/);
  say('Done! Score '+(m?m[1]+'/100 (grade '+m[2]+')':'')+'.','ok',l?{href:l[0],text:'Open the full report'}:null);btn.disabled=false;return;}
 if(i>=45){say('Still running. Check back in a few minutes: ','',{href:'https://github.com/'+REPO+'/issues/'+n,text:'see progress'});btn.disabled=false;return;}
 say('Testing your server... this takes one to three minutes ('+(i*10)+'s)');setTimeout(function(){poll(n,i+1)},10000);
 }).catch(function(){setTimeout(function(){poll(n,i+1)},10000)});}
f.addEventListener('submit',function(e){e.preventDefault();var t=f.querySelector('[name=cf-turnstile-response]');
 btn.disabled=true;say('Sending your request...');
 fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:f.elements.url.value.trim(),consent:f.elements.consent.checked,token:t?t.value:''})})
 .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){
  if(!x.ok){say(x.j.error||'Something went wrong.','err');btn.disabled=false;if(window.turnstile)turnstile.reset();return;}
  poll(x.j.issue,0);}).catch(function(){say('Could not reach the test service. Please try again.','err');btn.disabled=false;});});})();
"""


def _submit_block(config: dict[str, str]) -> str:
    issue_btn = f'<a class="btn" href="{SUBMIT_URL}">Use the GitHub form instead</a>'
    if not config:
        return (f'<ol class="steps"><li><b>Open the form</b><span>Click the button below. It opens a short form on GitHub.</span></li>'
                f'<li><b>Paste your server\'s address</b><span>It must be a public <code>https://</code> MCP server that you own or '
                f'have permission to test.</span></li><li><b>Get your report</b><span>A robot tests it and replies with the score. '
                f'It then appears on this page.</span></li></ol><div class="btns" style="margin-top:18px">'
                f'<a class="btn primary" href="{SUBMIT_URL}">Request a test</a></div>')
    api, key = escape(config["submit_api"], quote=True), escape(config["turnstile_sitekey"], quote=True)
    return (
        f'<div class="card"><form id="sf" data-api="{api}" style="display:grid;gap:14px">'
        '<label><b>Your server\'s address</b><br><input name="url" type="url" required placeholder="https://example.com/mcp" '
        'style="width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--bg);color:var(--fg);font:inherit"></label>'
        '<label style="display:flex;gap:10px;align-items:flex-start"><input name="consent" type="checkbox" required style="margin-top:6px">'
        '<span>I own this server, or I have permission to test it, and I am happy for the result to be public.</span></label>'
        f'<div class="cf-turnstile" data-sitekey="{key}"></div>'
        '<div><button class="btn primary" type="submit" style="cursor:pointer;font:inherit;font-weight:600">Test my server</button></div>'
        '<div id="sf-out" class="note" role="status" aria-live="polite">Free. Takes one to three minutes. No sign-up needed.</div>'
        f'</form></div><div class="btns" style="margin-top:14px">{issue_btn}</div>'
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        f'<script>{_FORM_JS}</script>')


def _index(title: str, rows: list[dict[str, Any]], config: dict[str, str] | None = None) -> str:
    n = len(rows)
    avg = round(sum(r["score"] or 0 for r in rows) / n) if n else 0
    serious = sum(r["critical"] + r["high"] for r in rows)
    healthy = sum(1 for r in rows if (r["score"] or 0) >= 80)
    stamp = datetime.now(UTC).strftime("%d %b %Y, %H:%M UTC")
    table = "".join(_row_html(i, r) for i, r in enumerate(rows, 1))
    legend = "".join(
        f'<div>{grade_chip(g)}<span><b>{lo}</b> &ndash; {txt}</span></div>' for g, lo, txt in (
            ("A", "90+", "Excellent"), ("B", "80+", "Good"), ("C", "70+", "Needs work"), ("D", "60+", "Poor"),
            ("F", "below 60", "Failing")))
    body = f"""
<header class="hero">
<span class="eyebrow">Free &amp; open source &middot; no sign-up to read</span>
<h1>Is your AI tool server<br>healthy and safe?</h1>
<p class="lead">AI assistants like Claude and ChatGPT use small programs called <b>MCP servers</b> to read files,
search databases and call other apps. <b>MCPDoctor</b> tests those servers the way an AI would use them, and gives each
one a score from 0 to 100 &mdash; so you can see problems <i>before</i> they cause trouble.</p>
<div class="btns"><a class="btn primary" href="#submit">Test my server</a>
<a class="btn" href="#board">See the leaderboard</a><a class="btn" href="{REPO}">View source</a></div>
<div class="stats">
<div class="stat"><b>{n}</b><span>servers tested</span></div>
<div class="stat"><b>{avg}</b><span>average score</span></div>
<div class="stat"><b>{healthy}</b><span>scoring 80 or more</span></div>
<div class="stat"><b>{serious}</b><span>serious problems found</span></div></div>
</header>

<section id="what"><h2>What is this, in plain words?</h2>
<p class="sub">If an AI assistant is a smart intern, an MCP server is a toolbox you hand it. A badly labelled toolbox
confuses the intern; a booby-trapped one can hurt you. We open the toolbox and check.</p>
<div class="grid">
<div class="card"><span class="ico">&#129520;</span><h3>Quality</h3><p>Are the tools named and described clearly enough
that an AI picks the right one and fills it in correctly?</p></div>
<div class="card"><span class="ico">&#128737;&#65039;</span><h3>Security</h3><p>Is anything hidden in the descriptions to
steer the AI? Can the tools be tricked into leaking secrets, reading private files or running commands?</p></div>
<div class="card"><span class="ico">&#9889;</span><h3>Reliability</h3><p>Does the server keep working when it gets
unusual input &mdash; or does it crash, hang or fail quietly?</p></div></div></section>

<section id="board"><h2>Leaderboard</h2>
<p class="sub">Ranked by overall score. Click a server for the full report: what was found, the evidence, and how to fix it.
<b>Demo</b> servers are small examples we built on purpose, some of them broken, to show what the checks catch.
<b>Community</b> servers were submitted by their owners.</p>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Server</th><th>Score</th><th>Security</th><th>Quality</th>
<th>Reliability</th><th>Serious issues</th><th>Tools</th></tr></thead><tbody>{table}</tbody></table></div></section>

<section><h2>How to read a score</h2>
<p class="sub">Every problem found takes points off. Serious problems take off a lot, and a critical problem caps the
whole score at 49 &mdash; one open door matters more than many tidy rooms.</p>
<div class="legend">{legend}</div></section>

<section id="submit"><h2>Get your own server tested</h2>
<p class="sub">Paste the public address of your MCP server and get a free score and a list of fixes.</p>
{_submit_block(config or {})}
<p class="note" style="margin-top:16px"><b>Fair-use limits:</b> to keep this free, only <b>{DAILY_LIMIT} servers per day</b>
are tested in total ({PER_USER_LIMIT} per person). If today is full, try again tomorrow. Results are public. Only submit servers you are
allowed to test. We never store logins or keys; servers that need a login can't be tested here &mdash; run MCPDoctor
yourself instead: <code>pip install git+https://github.com/NANDAN-CREATOR/mcpdoctor</code>.</p></section>

<section><h2>Questions</h2>
<details><summary>What does a good score mean?</summary><p>That our checks found nothing wrong. It does not prove a server is
safe &mdash; every report lists which checks ran and which didn't.</p></details>
<details><summary>Does testing harm my server?</summary><p>The test makes a few dozen ordinary calls plus some deliberately
odd inputs (like very long text) to see how it copes. Tools that look destructive, such as delete or send, are skipped
by default.</p></details>
<details><summary>Can I remove my result?</summary><p>Yes. Open an issue on GitHub asking for removal and it will be deleted.</p></details>
<details><summary>Can I run it myself instead?</summary><p>Yes, it is free and open source:
<code>pip install git+https://github.com/NANDAN-CREATOR/mcpdoctor</code> then <code>mcpdoctor scan --url https://your-server/mcp</code>. See the
<a href="{REPO}#readme">README</a>.</p></details></section>

<footer>Refreshed {stamp} &middot; MCPDoctor {__version__} &middot; <a href="{REPO}">GitHub</a> &middot;
<a href="{REPO}#how-scoring-works">How scoring works</a> &middot; <a href="leaderboard.json">Data (JSON)</a></footer>
"""
    return page(title, body, description="Free health and security scores for MCP servers used by AI assistants.")


__all__ = ["build", "slugify", "load_entries", "row_from_report", "badge_color"]
