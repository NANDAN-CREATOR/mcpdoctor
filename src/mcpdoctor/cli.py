"""Command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import click

from mcpdoctor import __version__
from mcpdoctor.evals.llm import LlmConfig, LlmError
from mcpdoctor.models import Report, Severity
from mcpdoctor.pin import DEFAULT_LOCKFILE, build_lock, write_lock
from mcpdoctor.report import (
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
    score_badge,
)
from mcpdoctor.rules import RULES
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.sandbox import SandboxConfig, docker_available
from mcpdoctor.settings import Settings, SettingsError, load_settings
from mcpdoctor.target import Target, TargetError, load_config_targets, parse_kv

FAIL_CHOICES = ["none", "info", "low", "medium", "high", "critical"]

EXIT_OK, EXIT_GATE, EXIT_USAGE = 0, 1, 2


class UsageFailure(click.ClickException):
    exit_code = EXIT_USAGE


def _fail(message: str) -> click.ClickException:
    return UsageFailure(message)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version", prog_name="mcpdoctor")
def main() -> None:
    """MCPDoctor - test MCP servers for quality, safety and agent-readiness.

    \b
    Typical use:
      mcpdoctor scan -- python my_server.py          # local server over stdio
      mcpdoctor scan --url https://host/mcp          # remote server
      mcpdoctor scan --mcp-config ~/.cursor/mcp.json --all
      mcpdoctor scan --sandbox --image python:3.12-slim --mount ./srv:/app -- python /app/server.py

    Exit status: 0 = gate passed, 1 = findings at/above --fail-on (or score below --min-score),
    2 = usage or setup error.
    """


# --------------------------------------------------------------------------------------------- scan
@main.command("scan", context_settings={"ignore_unknown_options": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@click.option("--url", help="Scan a remote Streamable HTTP server instead of a local command.")
@click.option("--header", "headers", multiple=True, metavar="KEY=VALUE", help="HTTP header for --url (repeatable).")
@click.option("--mcp-config", "mcp_config", type=click.Path(dir_okay=False), help="Claude/Cursor/VS Code style MCP config file.")
@click.option("--server", "server_name", help="With --mcp-config: scan only this server.")
@click.option("--all", "scan_all", is_flag=True, help="With --mcp-config: scan every server in the file.")
@click.option("--env", "env_pairs", multiple=True, metavar="KEY=VALUE", help="Environment variable for the server (repeatable).")
@click.option("--pass-env", "pass_env", multiple=True, metavar="NAME", help="Forward NAME from your environment to the server.")
@click.option("--static-only", is_flag=True, help="Analyse definitions only; never execute a tool.")
@click.option("--probe-all", is_flag=True, help="Also call tools that look destructive (use inside --sandbox).")
@click.option("--probes", help="Comma-separated subset of probes to run (see docs).")
@click.option("--repeats", type=click.IntRange(1, 20), default=3, show_default=True, help="Calls per tool in the contract test.")
@click.option("--max-calls", type=int, help="Maximum tool calls (default 700).")
@click.option("--time-budget", type=float, help="Maximum seconds spent probing (default 300).")
@click.option("--call-timeout", type=float, default=20.0, show_default=True, help="Seconds before a tool call counts as hung.")
@click.option("--slow-ms", type=float, help="Latency (ms) above which a tool is reported slow (default 5000).")
@click.option("--sandbox", is_flag=True, help="Run the server inside a locked-down Docker container.")
@click.option("--image", help="Docker image that contains the server (with --sandbox).")
@click.option("--mount", "mounts", multiple=True, metavar="HOST:CONTAINER[:ro|rw]", help="Extra bind mount for the sandbox (read-only by default).")
@click.option("--sandbox-network", type=click.Choice(["none", "bridge"]), default="none", show_default=True)
@click.option("--lockfile", type=click.Path(dir_okay=False), help="Compare tool definitions with a pinned lock file.")
@click.option("--llm", "llm_provider", metavar="PROVIDER", help="Run the agent evaluation with: gemini, groq, openrouter, ollama, openai, or custom (with --llm-base-url).")
@click.option("--model", help="Model name for --llm (overrides the provider default).")
@click.option("--llm-base-url", help="Custom OpenAI-compatible base URL.")
@click.option("--llm-key-env", help="Name of the environment variable holding the API key.")
@click.option("--llm-rpm", type=int, help="Requests per minute to stay under (default 15).")
@click.option("--eval-tasks", type=click.IntRange(1, 10), default=2, show_default=True, help="Test requests generated per tool.")
@click.option("--tasks-file", type=click.Path(dir_okay=False), help="Cache of generated test requests (reuse to freeze the benchmark).")
@click.option("--eval-execute", is_flag=True, help="Also execute the model's chosen calls (safe tools only unless --probe-all).")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif", "markdown", "html"]), default="terminal", show_default=True)
@click.option("--output", "-o", type=click.Path(dir_okay=False), help="Write the --format report to this file instead of stdout.")
@click.option("--json", "json_out", type=click.Path(dir_okay=False), help="Also write a JSON report.")
@click.option("--sarif", "sarif_out", type=click.Path(dir_okay=False), help="Also write a SARIF report (GitHub code scanning).")
@click.option("--markdown", "markdown_out", type=click.Path(dir_okay=False), help="Also write a Markdown report (PR comments).")
@click.option("--html", "html_out", type=click.Path(dir_okay=False), help="Also write a self-contained HTML report.")
@click.option("--badge", "badge_out", type=click.Path(dir_okay=False), help="Also write an SVG score badge.")
@click.option("--fail-on", type=click.Choice(FAIL_CHOICES), help="Exit 1 if any finding is at/above this severity (default high).")
@click.option("--min-score", type=click.IntRange(0, 100), help="Exit 1 if the overall score is below this.")
@click.option("--settings", "settings_path", type=click.Path(dir_okay=False), help="Settings file (default: ./.mcpdoctor.yml).")
@click.option("--verbose", "-v", is_flag=True, help="Show evidence and fix advice for every finding.")
@click.option("--min-severity", type=click.Choice(["info", "low", "medium", "high", "critical"]), default="info", show_default=True, help="Hide findings below this severity in the terminal report.")
def scan_cmd(command: tuple[str, ...], url: str | None, headers: tuple[str, ...], mcp_config: str | None,
             server_name: str | None, scan_all: bool, env_pairs: tuple[str, ...], pass_env: tuple[str, ...],
             static_only: bool, probe_all: bool, probes: str | None, repeats: int, max_calls: int | None,
             time_budget: float | None, call_timeout: float, slow_ms: float | None, sandbox: bool,
             image: str | None, mounts: tuple[str, ...], sandbox_network: str, lockfile: str | None,
             llm_provider: str | None, model: str | None, llm_base_url: str | None, llm_key_env: str | None,
             llm_rpm: int | None, eval_tasks: int, tasks_file: str | None, eval_execute: bool, fmt: str,
             output: str | None, json_out: str | None, sarif_out: str | None, markdown_out: str | None,
             html_out: str | None, badge_out: str | None, fail_on: str | None, min_score: int | None,
             settings_path: str | None, verbose: bool, min_severity: str) -> None:
    """Scan an MCP server: lint, security analysis, live probes, optional agent evaluation."""
    try:
        settings = load_settings(settings_path)
        targets = _resolve_targets(command, url, headers, mcp_config, server_name, scan_all, env_pairs)
        opts = _build_options(settings, static_only, probe_all, probes, repeats, max_calls, time_budget,
                              call_timeout, slow_ms, sandbox, image, mounts, sandbox_network, lockfile,
                              llm_provider, model, llm_base_url, llm_key_env, llm_rpm, eval_tasks, tasks_file,
                              eval_execute, pass_env, env_pairs)
    except (TargetError, SettingsError, LlmError, ValueError) as exc:
        raise _fail(str(exc)) from exc

    reports: list[Report] = []
    for target in targets:
        click.echo(click.style(f"Scanning {target.label} ...", fg="bright_black"), err=True)
        reports.append(asyncio.run(scan(target, opts)))

    multi = len(reports) > 1
    for report in reports:
        suffix = report.target if multi else None
        _emit(report, fmt, output, suffix, verbose, Severity.parse(min_severity))
        for path, renderer in ((json_out, render_json), (sarif_out, render_sarif), (markdown_out, render_markdown),
                               (html_out, render_html), (badge_out, score_badge)):
            if path:
                _write(_suffix_path(path, suffix), renderer(report))

    gate_fail = fail_on or settings.fail_on or "high"
    threshold = None if gate_fail == "none" else Severity.parse(gate_fail)
    floor = min_score if min_score is not None else settings.min_score
    failed = False
    for r in reports:
        why = []
        if threshold is not None and any(f.severity.rank >= threshold.rank for f in r.findings):
            n = sum(1 for f in r.findings if f.severity.rank >= threshold.rank)
            why.append(f"{n} finding(s) at or above '{threshold.value}'")
        if floor is not None and (r.scores.get("overall") or 0) < floor:
            why.append(f"score {r.scores.get('overall')} is below the minimum {floor}")
        if why:
            failed = True
            click.echo(click.style(f"FAIL {r.target}: {'; '.join(why)}", fg="red", bold=True), err=True)
        else:
            click.echo(click.style(f"PASS {r.target}: score {r.scores.get('overall')} ({r.scores.get('grade')})",
                                   fg="green", bold=True), err=True)
    sys.exit(EXIT_GATE if failed else EXIT_OK)


def _resolve_targets(command: tuple[str, ...], url: str | None, headers: tuple[str, ...], mcp_config: str | None,
                     server_name: str | None, scan_all: bool, env_pairs: tuple[str, ...]) -> list[Target]:
    given = sum(bool(x) for x in (command, url, mcp_config))
    if given != 1:
        raise TargetError("give exactly one target: a command after '--', or --url, or --mcp-config")
    env = parse_kv(env_pairs, "--env")
    if url:
        return [Target.from_url(url, headers=parse_kv(headers, "--header"))]
    if mcp_config:
        if not server_name and not scan_all:
            names = [t.label for t in load_config_targets(mcp_config)]
            raise TargetError(f"--mcp-config needs --server NAME or --all; servers in the file: {', '.join(names)}")
        found = load_config_targets(mcp_config, only=server_name)
        for t in found:
            t.env = {**t.env, **env}
        return found
    return [Target.from_command(list(command), env=env)]


def _build_options(settings: Settings, static_only: bool, probe_all: bool, probes: str | None, repeats: int,
                   max_calls: int | None, time_budget: float | None, call_timeout: float, slow_ms: float | None,
                   sandbox: bool, image: str | None, mounts: tuple[str, ...], sandbox_network: str,
                   lockfile: str | None, llm_provider: str | None, model: str | None, llm_base_url: str | None,
                   llm_key_env: str | None, llm_rpm: int | None, eval_tasks: int, tasks_file: str | None,
                   eval_execute: bool, pass_env: tuple[str, ...], env_pairs: tuple[str, ...]) -> ScanOptions:
    from mcpdoctor.probes import PROBES

    sb: SandboxConfig | None = None
    if sandbox:
        if not image:
            raise TargetError("--sandbox needs --image (a Docker image that contains the server and its dependencies)")
        ok, detail = docker_available()
        if not ok:
            raise TargetError(f"--sandbox needs Docker: {detail}")
        sb = SandboxConfig(image=image, mounts=list(mounts), network=sandbox_network)
    elif image or mounts:
        raise TargetError("--image / --mount only make sense together with --sandbox")
    only = None
    if probes:
        only = {p.strip() for p in probes.split(",") if p.strip()}
        valid = {n for n, _ in PROBES}
        bad = only - valid
        if bad:
            raise TargetError(f"unknown probe(s): {', '.join(sorted(bad))}; valid: {', '.join(sorted(valid))}")
    forward = {name: os.environ[name] for name in pass_env if name in os.environ}
    missing = [n for n in pass_env if n not in os.environ]
    if missing:
        raise TargetError(f"--pass-env: not set in your environment: {', '.join(missing)}")
    llm = None
    if llm_provider:
        llm = LlmConfig.resolve(llm_provider, model, llm_base_url, llm_key_env, llm_rpm)
    return ScanOptions(
        static_only=static_only, probe_all=probe_all, sandbox=sb, lockfile=lockfile, probes=only, repeats=repeats,
        max_calls=max_calls or settings.max_calls or 700, time_budget_s=time_budget or 300.0,
        call_timeout=call_timeout, slow_ms=slow_ms or settings.slow_ms or 5000.0, forward_env=forward,
        lint=settings.lint, llm=llm, eval_per_tool=eval_tasks, tasks_file=tasks_file, eval_execute=eval_execute,
        ignore_rules=set(settings.ignore_rules), ignore_pairs=set(settings.ignore_pairs))


def _suffix_path(path: str, suffix: str | None) -> str:
    if not suffix:
        return path
    from mcpdoctor.leaderboard import slugify

    p = Path(path)
    return str(p.with_name(f"{p.stem}.{slugify(suffix)}{p.suffix}"))


def _write(path: str, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    click.echo(f"wrote {p}", err=True)


def _emit(report: Report, fmt: str, output: str | None, suffix: str | None, verbose: bool, min_sev: Severity) -> None:
    if fmt == "terminal":
        text = render_terminal(report, verbose=verbose, min_severity=min_sev)
        if output:
            _write(_suffix_path(output, suffix), click.unstyle(text))
        else:
            click.echo(text)
        return
    renderer: Any = {"json": render_json, "sarif": render_sarif, "markdown": render_markdown,
                     "html": render_html}[fmt]
    text = renderer(report)
    if output:
        _write(_suffix_path(output, suffix), text)
    else:
        click.echo(text, nl=False)


# --------------------------------------------------------------------------------------------- pin
@main.command(context_settings={"ignore_unknown_options": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@click.option("--url", help="Pin a remote server.")
@click.option("--header", "headers", multiple=True, metavar="KEY=VALUE")
@click.option("--env", "env_pairs", multiple=True, metavar="KEY=VALUE")
@click.option("--output", "-o", default=DEFAULT_LOCKFILE, show_default=True, type=click.Path(dir_okay=False))
def pin(command: tuple[str, ...], url: str | None, headers: tuple[str, ...], env_pairs: tuple[str, ...],
        output: str) -> None:
    """Record the current tool definitions in a lock file (commit it; verify with `scan --lockfile`)."""
    try:
        targets = _resolve_targets(command, url, headers, None, None, False, env_pairs)
    except TargetError as exc:
        raise _fail(str(exc)) from exc
    report = asyncio.run(scan(targets[0], ScanOptions(static_only=True)))
    if not report.tools:
        raise _fail("could not read any tools from the server: " + "; ".join(f.message for f in report.findings[:2]))
    write_lock(output, build_lock(report.tools, report.server, report.target))
    click.echo(f"pinned {len(report.tools)} tool(s) to {output}")


# --------------------------------------------------------------------------------------------- rules
@main.command()
@click.argument("rule_id", required=False)
@click.option("--format", "fmt", type=click.Choice(["table", "json", "markdown"]), default="table")
def rules(rule_id: str | None, fmt: str) -> None:
    """List every check, or explain one (for example: mcpdoctor rules D001)."""
    if rule_id:
        r = RULES.get(rule_id.upper())
        if r is None:
            raise _fail(f"unknown rule {rule_id!r}")
        click.echo(f"{r.id}  {r.title}\n  category: {r.category.value}   default severity: {r.severity.value}"
                   f"   runs tools: {'yes' if r.dynamic else 'no'}\n  refs: {', '.join(r.refs) or '-'}\n\n"
                   f"  Why it matters\n    {r.why}\n\n  How to fix\n    {r.fix}")
        return
    if fmt == "json":
        click.echo(json.dumps([{"id": r.id, "title": r.title, "category": r.category.value,
                                "severity": r.severity.value, "why": r.why, "fix": r.fix, "refs": list(r.refs),
                                "dynamic": r.dynamic} for r in RULES.values()], indent=2))
    elif fmt == "markdown":
        click.echo(rules_markdown())
    else:
        for r in RULES.values():
            click.echo(f"{r.id}  {r.severity.value:8} {r.category.value:9} {r.title}")


def rules_markdown() -> str:
    out = ["# Rule reference", "", "Generated from `src/mcpdoctor/rules.py` by `scripts/gen_rules_doc.py`. "
           "Do not edit by hand.", "", "| ID | Severity | Category | Runs tools | Title |", "|---|---|---|---|---|"]
    for r in RULES.values():
        out.append(f"| [{r.id}](#{r.id.lower()}) | {r.severity.value} | {r.category.value} | "
                   f"{'yes' if r.dynamic else 'no'} | {r.title} |")
    for r in RULES.values():
        out += ["", f'<a id="{r.id.lower()}"></a>', f"## {r.id} - {r.title}", "",
                f"- **Default severity:** {r.severity.value}", f"- **Category:** {r.category.value}",
                f"- **Executes tools:** {'yes' if r.dynamic else 'no'}"]
        if r.refs:
            out.append(f"- **References:** {', '.join(r.refs)}")
        out += ["", f"**Why it matters.** {r.why}", "", f"**How to fix.** {r.fix}"]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------- init
@main.command()
@click.option("--command", "server_command", default="python server.py", show_default=True,
              help="Command that starts your server (used in the workflow).")
@click.option("--force", is_flag=True, help="Overwrite existing files.")
def init(server_command: str, force: bool) -> None:
    """Add a settings file and a GitHub Actions workflow to the current repository."""
    files = {
        ".mcpdoctor.yml": (
            "# MCPDoctor settings - see https://github.com/NANDAN-CREATOR/mcpdoctor#configuration\n"
            "fail_on: high        # none | info | low | medium | high | critical\n"
            "min_score: 80\n"
            "# ignore:\n#   - Q015\n#   - rule: Q011\n#     tool: legacy_tool\n"),
        ".github/workflows/mcpdoctor.yml": (
            "name: MCPDoctor\non:\n  pull_request:\n  push:\n    branches: [main]\n\n"
            "permissions:\n  contents: read\n  security-events: write\n  pull-requests: write\n\n"
            "jobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n"
            "      - run: pip install -r requirements.txt  # your server's dependencies\n"
            "      - uses: NANDAN-CREATOR/mcpdoctor@v0\n        with:\n"
            f"          command: \"{server_command}\"\n          fail-on: high\n"),
    }
    for rel, text in files.items():
        p = Path(rel)
        if p.exists() and not force:
            click.echo(f"skipped {rel} (exists; use --force)")
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        click.echo(f"wrote {rel}")


# --------------------------------------------------------------------------------------------- leaderboard
@main.command()
@click.argument("servers_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default="site", show_default=True, type=click.Path(file_okay=False))
@click.option("--call-timeout", type=float, default=15.0, show_default=True)
@click.option("--time-budget", type=float, default=120.0, show_default=True, help="Probing seconds per server.")
def leaderboard(servers_file: str, out_dir: str, call_timeout: float, time_budget: float) -> None:
    """Scan every server listed in SERVERS_FILE (YAML) and write a static leaderboard site."""
    from mcpdoctor.leaderboard import build

    try:
        reports = asyncio.run(build(servers_file, out_dir, ScanOptions(call_timeout=call_timeout,
                                                                      time_budget_s=time_budget)))
    except TargetError as exc:
        raise _fail(str(exc)) from exc
    for r in reports:
        click.echo(f"{r.scores.get('overall', '?'):>4} {r.scores.get('grade', '?')}  {r.target}")
    click.echo(f"wrote {out_dir}/index.html")


# --------------------------------------------------------------------------------------------- check-env
@main.command("check-env")
def check_env() -> None:
    """Show versions and whether Docker (for --sandbox) is usable."""
    from importlib import metadata

    def ver(pkg: str) -> str:
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            return "not installed"

    ok, detail = docker_available()
    click.echo(f"mcpdoctor {__version__}\npython    {platform.python_version()} on {platform.system()}\n"
               f"mcp sdk    {ver('mcp')}\ndocker     {'ready (server ' + detail + ')' if ok else 'unavailable: ' + detail}")
    for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        click.echo(f"{name:20} {'set' if os.environ.get(name) else 'not set'}")


if __name__ == "__main__":
    main()
