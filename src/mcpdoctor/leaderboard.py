"""Scan a list of servers and publish a static leaderboard site (used by the nightly GitHub Pages workflow)."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

import yaml

from mcpdoctor import __version__
from mcpdoctor.models import Report, Severity
from mcpdoctor.report import render_html, render_json, score_badge
from mcpdoctor.report.html import CSS
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.sandbox import SandboxConfig
from mcpdoctor.scoring import badge_color
from mcpdoctor.target import Target, TargetError


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


async def build(entries_file: str | Path, out_dir: str | Path, base: ScanOptions) -> list[Report]:
    title, entries = load_entries(entries_file)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports: list[Report] = []
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
    reports.sort(key=lambda r: (-(r.scores.get("overall") or 0), r.target))
    (out / "index.html").write_text(_index(title, reports))
    (out / "leaderboard.json").write_text(json.dumps({
        "schema": "mcpdoctor.leaderboard/1", "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "servers": [{"name": r.target, "score": r.scores.get("overall"), "grade": r.scores.get("grade"),
                     "counts": r.counts(), "tools": len(r.tools)} for r in reports]}, indent=2) + "\n")
    (out / ".nojekyll").write_text("")
    return reports


def _index(title: str, reports: list[Report]) -> str:
    rows = []
    for i, r in enumerate(reports, 1):
        c = r.counts()
        grade = r.scores.get("grade", "?")
        cats = r.scores.get("categories", {})

        def cell(name: str, cats: dict[str, Any] = cats) -> str:
            v = cats.get(name, {})
            return f"{v['score']}" if v.get("assessed") else "-"

        rows.append(
            f"<tr><td>{i}</td><td><a href='{slugify(r.target)}.html' style='color:var(--accent)'>"
            f"{escape(r.target)}</a></td><td><b>{r.scores.get('overall', '?')}</b> "
            f"<span class='grade' style='background:{badge_color(grade)};font-size:.8rem;padding:1px 8px'>{escape(str(grade))}</span></td>"
            f"<td>{cell('security')}</td><td>{cell('quality')}</td><td>{cell('reliability')}</td>"
            f"<td>{c[Severity.CRITICAL.value]}/{c[Severity.HIGH.value]}</td><td>{len(r.tools)}</td></tr>")
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head><body><main>
<h1>{escape(title)}</h1>
<p class="muted">Tested {stamp} with MCPDoctor {__version__}. Scores combine security, quality and reliability
(see the <a style="color:var(--accent)" href="https://github.com/NANDAN-CREATOR/mcpdoctor#how-scoring-works">scoring model</a>).
A good score means MCPDoctor found nothing wrong with the checks it ran, not that a server is proven safe.</p>
<div class="card"><table><thead><tr><th>#</th><th>Server</th><th>Score</th><th>Security</th><th>Quality</th>
<th>Reliability</th><th>Crit/High</th><th>Tools</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
</main></body></html>
"""
