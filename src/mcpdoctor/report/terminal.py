from __future__ import annotations

import textwrap

import click

from mcpdoctor.models import Finding, Report, Severity
from mcpdoctor.textutil import clean

_SEV_STYLE = {
    Severity.CRITICAL: {"fg": "red", "bold": True},
    Severity.HIGH: {"fg": "red"},
    Severity.MEDIUM: {"fg": "yellow"},
    Severity.LOW: {"fg": "cyan"},
    Severity.INFO: {"fg": "bright_black"},
}
_GRADE_STYLE = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}


def _wrap(text: str, indent: str, width: int = 100) -> str:
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def _finding_block(f: Finding, verbose: bool) -> str:
    sev = click.style(f"{f.severity.value.upper():8}", **_SEV_STYLE[f.severity])  # type: ignore[arg-type]
    where = f" {click.style(f.tool, bold=True)}" if f.tool else ""
    head = f"  {sev} {f.rule_id}{where}  {f.title}"
    lines = [head, _wrap(f.message, "      ")]
    if f.evidence and (verbose or f.severity.rank >= Severity.MEDIUM.rank):
        lines.append(_wrap(f"evidence: {f.evidence}", "      ", 100))
    if verbose or f.severity.rank >= Severity.HIGH.rank:
        lines.append(click.style(_wrap(f"fix: {f.fix}", "      "), fg="green"))
    return "\n".join(lines)


def _safe(report: Report) -> Report:
    """A hostile server controls tool names, messages and evidence: never let it write escape codes to a terminal."""
    from dataclasses import replace

    return replace(
        report,
        target=clean(report.target),
        server=replace(report.server, name=clean(report.server.name), version=clean(report.server.version)),
        findings=[replace(f, message=clean(f.message), evidence=clean(f.evidence) if f.evidence else f.evidence,
                          tool=clean(f.tool) if f.tool else f.tool, fix=clean(f.fix)) for f in report.findings],
        coverage=[replace(c, detail=clean(c.detail)) for c in report.coverage],
    )


def render_terminal(report: Report, *, verbose: bool = False, min_severity: Severity = Severity.INFO) -> str:
    report = _safe(report)
    out: list[str] = []
    srv = report.server
    out.append(click.style(f"MCPDoctor {report.version}", bold=True) + f" - {report.target}")
    ident = f"{srv.name} {srv.version}".strip()
    out.append(f"server: {ident} (protocol {srv.protocol_version or 'n/a'}) - {len(report.tools)} tool(s) - "
               f"{report.duration_s:.1f}s - {report.evaluation.get('calls_made', 0)} tool call(s) made")
    out.append("")

    sc = report.scores
    if sc:
        grade = sc.get("grade", "?")
        head = click.style(f"SCORE {sc['overall']}/100  {grade}", bold=True, fg=_GRADE_STYLE.get(grade, "white"))
        parts = []
        for name, c in sc["categories"].items():
            parts.append(f"{name} {c['score']} {c['grade']}" if c["assessed"] else f"{name} not tested")
        out.append(f"{head}    ({' | '.join(parts)})")
        for cap in sc.get("caps", []):
            out.append(click.style(f"  cap: {cap}", fg="yellow"))
        out.append("")

    shown = report.by_severity(min_severity)
    counts = report.counts()
    summary = ", ".join(f"{counts[s.value]} {s.value}" for s in reversed(list(Severity)) if counts[s.value])
    out.append(click.style(f"FINDINGS ({len(report.findings)})", bold=True) + (f"  {summary}" if summary else ""))
    if not shown:
        out.append("  none")
    for f in shown:
        out.append(_finding_block(f, verbose))
    out.append("")

    ag = report.evaluation.get("agent")
    if ag:
        out.append(click.style("AGENT EVALUATION", bold=True) + f"  {ag['provider']}/{ag['model']}")
        out.append(f"  tool selection accuracy: {ag['tool_selection_accuracy']}   argument validity: "
                   f"{ag['argument_validity']}   avg prompt tokens/request: {ag['avg_prompt_tokens_per_request']}")
        out.append("")

    out.append(click.style("COVERAGE", bold=True) + "  (what was actually tested)")
    tag = {"ran": click.style("ran    ", fg="green"), "skipped": click.style("skipped", fg="yellow"),
           "not_applicable": click.style("n/a    ", fg="bright_black")}
    for c in report.coverage:
        out.append(f"  {tag.get(c.status, c.status):8} {c.name:20} {c.detail}")
    sup = report.options.get("suppressed")
    if sup:
        out.append(f"  ({len(sup)} finding(s) suppressed by configuration)")
    return "\n".join(out) + "\n"
