"""Orchestration: take a target, run every enabled check, and return a :class:`~mcpdoctor.models.Report`."""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mcpdoctor import __version__, scoring
from mcpdoctor.evals.agent import generate_tasks, load_cached_tasks, run_agent_eval, save_tasks
from mcpdoctor.evals.llm import ChatClient, LlmConfig, LlmError
from mcpdoctor.http_checks import check_http_target, soften_open_access
from mcpdoctor.lint import LintConfig, lint_tools
from mcpdoctor.models import Coverage, Finding, Report
from mcpdoctor.pin import compare_lock, read_lock
from mcpdoctor.probes import ProbeConfig, ProbeContext, run_probes
from mcpdoctor.rules import make_finding
from mcpdoctor.sandbox import SandboxConfig, force_remove, sandbox_target
from mcpdoctor.security_static import scan_metadata
from mcpdoctor.session import McpSession, StartupError
from mcpdoctor.target import Isolation, Target


@dataclass
class ScanOptions:
    static_only: bool = False
    probe_all: bool = False
    sandbox: SandboxConfig | None = None
    lockfile: str | None = None
    probes: set[str] | None = None
    max_calls: int = 700
    time_budget_s: float = 300.0
    call_timeout: float = 20.0
    init_timeout: float = 45.0
    slow_ms: float = 5000.0
    repeats: int = 3
    forward_env: dict[str, str] = field(default_factory=dict)
    lint: LintConfig = field(default_factory=LintConfig)
    llm: LlmConfig | None = None
    eval_per_tool: int = 2
    tasks_file: str | None = None
    eval_execute: bool = False
    ignore_rules: set[str] = field(default_factory=set)
    ignore_pairs: set[tuple[str, str]] = field(default_factory=set)  # (rule_id, tool)


async def scan(target: Target, opts: ScanOptions) -> Report:
    started = datetime.now(UTC)
    t0 = time.perf_counter()
    report = Report(target=target.label, version=__version__, started_at=started.isoformat(timespec="seconds"))
    report.options = {
        "static_only": opts.static_only, "probe_all": opts.probe_all, "sandbox": bool(opts.sandbox),
        "transport": target.kind, "llm": (f"{opts.llm.provider}/{opts.llm.model}" if opts.llm else None),
    }
    iso: Isolation | None = None
    session: McpSession | None = None
    sandbox_name: str | None = None
    try:
        run_target = target
        if target.kind == "stdio":
            iso = Isolation.create(extra_env=opts.forward_env)
            if opts.sandbox:
                sandbox_name = opts.sandbox.name
                run_target = sandbox_target(target, opts.sandbox, iso)

        if target.kind == "http":
            http_findings, http_cover = await asyncio.to_thread(check_http_target, target)
            report.findings.extend(http_findings)
            report.coverage.extend(http_cover)

        async def factory() -> McpSession | None:
            s = McpSession(run_target, iso, call_timeout=opts.call_timeout, init_timeout=opts.init_timeout)
            try:
                await s.start()
            except StartupError:
                await s.close()
                return None
            return s

        session = McpSession(run_target, iso, call_timeout=opts.call_timeout, init_timeout=opts.init_timeout)
        try:
            await session.start()
        except StartupError as exc:
            report.findings.append(make_finding(
                "P001", str(exc), evidence=(exc.stderr_tail or "")[-380:] or None))
            report.coverage.append(Coverage("startup", "ran", "handshake failed; nothing else could be tested"))
            _finish(report, opts, t0, assessed={"reliability"})
            return report

        report.server = session.identity
        if session.startup_ms > 5000:
            report.findings.append(make_finding("P003", f"The MCP handshake took {session.startup_ms / 1000:.1f}s."))
        try:
            tools = await session.list_tools()
        except Exception as exc:
            report.findings.append(make_finding("P001", f"Handshake succeeded but tools/list failed: {exc}"))
            _finish(report, opts, t0, assessed={"reliability"})
            return report
        report.tools = tools

        if not tools:
            report.findings.append(make_finding("P004", "tools/list returned an empty list."))
            report.coverage.append(Coverage("static-analysis", "not_applicable", "no tools to analyse"))
            _finish(report, opts, t0, assessed={"reliability"})
            return report

        # ---- static analysis (never executes a tool)
        report.findings.extend(lint_tools(tools, opts.lint))
        report.findings = soften_open_access(report.findings, tools)
        report.coverage.append(Coverage("lint", "ran", f"{len(tools)} tool definition(s) checked for quality"))
        report.findings.extend(scan_metadata(tools, session.identity))
        report.coverage.append(Coverage(
            "tool-metadata-scan", "ran", "descriptions, schemas, defaults and server instructions scanned for "
            "hidden instructions, invisible characters, encoded payloads and secrets"))
        if opts.lockfile:
            try:
                report.findings.extend(compare_lock(read_lock(opts.lockfile), tools))
                report.coverage.append(Coverage("tool-pinning", "ran", f"compared with {opts.lockfile}"))
            except (OSError, ValueError) as exc:
                report.coverage.append(Coverage("tool-pinning", "skipped", f"lock file unreadable: {exc}"))
        else:
            report.coverage.append(Coverage("tool-pinning", "skipped", "no --lockfile given"))

        # ---- dynamic probes + optional LLM evaluation
        ctx = ProbeContext(
            session=session, session_factory=factory, isolation=iso, tools=tools,
            is_remote=target.is_remote,
            config=ProbeConfig(probe_all=opts.probe_all, max_calls=opts.max_calls, time_budget_s=opts.time_budget_s,
                               slow_ms=opts.slow_ms, sandboxed=opts.sandbox is not None and opts.sandbox.network == "none",
                               only=opts.probes, call_timeout=opts.call_timeout, repeats=opts.repeats))
        if opts.static_only:
            for name in ("contract", "input-validation", "env-leak", "path-traversal", "sql", "command-injection",
                         "ssrf", "unbounded-output", "definition-drift", "robustness"):
                ctx.cover(name, "skipped", "--static-only: no tool was executed")
        else:
            await run_probes(ctx)

        if opts.llm is not None:
            await _run_llm_eval(ctx, opts)

        report.findings.extend(ctx.findings)
        report.coverage.extend(ctx.coverage)
        report.evaluation.update(ctx.evaluation)
        # the session may have been replaced after a crash
        session = ctx.session
        assessed = {"security", "quality"} | (set() if opts.static_only else {"reliability"})
        _finish(report, opts, t0, assessed=assessed)
        return report
    finally:
        if session is not None:
            await session.close()
        if sandbox_name:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(force_remove, sandbox_name)
        if iso is not None:
            iso.cleanup()


async def _run_llm_eval(ctx: ProbeContext, opts: ScanOptions) -> None:
    assert opts.llm is not None
    client = ChatClient(opts.llm)
    try:
        tasks = None
        path = Path(opts.tasks_file) if opts.tasks_file else None
        if path is not None and path.exists():
            tasks = load_cached_tasks(path, ctx.tools)
        if tasks is None:
            tasks = await generate_tasks(client, ctx.tools, opts.eval_per_tool)
            if path is not None and tasks:
                save_tasks(path, ctx.tools, tasks, opts.llm.model)
        if not tasks:
            ctx.cover("agent-eval", "skipped", "the model produced no usable test requests")
            return
        summary = await run_agent_eval(ctx, client, tasks, execute=opts.eval_execute and not opts.static_only)
        ctx.evaluation["agent"] = summary
        detail = (f"{summary['answered']}/{summary['tasks']} requests answered by {opts.llm.provider}/"
                  f"{opts.llm.model}; selection accuracy {summary['tool_selection_accuracy']}")
        ctx.cover("agent-eval", "ran", detail)
        if summary.get("aborted"):
            ctx.cover("agent-eval-abort", "skipped", f"stopped after repeated provider errors: {summary['aborted']}")
    except LlmError as exc:
        ctx.cover("agent-eval", "skipped", f"LLM provider error: {exc}")


def _finish(report: Report, opts: ScanOptions, t0: float, assessed: set[str]) -> None:
    suppressed: list[Finding] = []
    kept: list[Finding] = []
    for f in report.findings:
        if f.rule_id in opts.ignore_rules or (f.rule_id, f.tool or "") in opts.ignore_pairs:
            suppressed.append(f)
        else:
            kept.append(f)
    report.findings = kept
    if suppressed:
        report.options["suppressed"] = [{"rule_id": f.rule_id, "tool": f.tool} for f in suppressed]
    report.duration_s = time.perf_counter() - t0
    report.scores = scoring.compute(report.findings, assessed)
