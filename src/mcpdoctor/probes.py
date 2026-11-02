"""Dynamic probes: run the server's tools and observe what happens.

Safety model
------------
* The server runs with a **fake HOME**, an **empty working directory** and **canary secrets**; it never sees
  the caller's environment variables unless they are explicitly forwarded.
* In the default ("safe") mode only tools that do not look destructive are called. A tool is skipped when its
  ``destructive_hint`` is true, or its name / first description word is a destructive verb (delete, write, send,
  update, ...). ``--probe-all`` lifts this, and is intended for use inside the Docker sandbox.
* Payloads are *detectors*, not weapons: they print a computed marker, read a planted canary, or call back to a
  loopback listener MCPDoctor itself owns. No payload deletes, encrypts or exfiltrates anything.
* Every probe reports in the coverage table whether it ran, so a clean result is never over-trusted.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import statistics
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jsonschema

from mcpdoctor.models import CallRecord, Coverage, Finding, Severity, ToolInfo
from mcpdoctor.rules import make_finding
from mcpdoctor.session import McpSession
from mcpdoctor.synth import minimal_args, param_type, sample_value, string_params
from mcpdoctor.target import Isolation
from mcpdoctor.textutil import name_tokens, snippet

# ----------------------------------------------------------------------------- detectors (pure functions)
PASSWD_RX = re.compile(r"root:[x*!]?:0:0:")
CMD_MARKER_RX = re.compile(r"MCPDOCTOR_42\b")
SQL_ERROR_RX = re.compile(
    r"(sqlite3?\.|OperationalError|ProgrammingError|SQLSTATE|SQL (logic )?error|SQL syntax|"
    r"syntax error at or near|near \"[^\"]*\": syntax error|unrecognized token|unterminated (quoted )?string|"
    r"unclosed quotation mark|ORA-\d{4,5}|psycopg|mysql_|MariaDB server|\bODBC\b|\bJDBC\b|incomplete input)",
    re.I)
TRACE_RX = re.compile(
    r"(Traceback \(most recent call last\)|File \"[^\"]+\", line \d+|\bat [\w.$<>\[\] ]+\([^)]*\.(js|ts|mjs|java|kt|cs):\d+|"
    r"/(?:home|Users|usr/lib|opt|srv|app|var/task)/[\w.\-/]+\.(?:py|js|ts|rb|go|rs|java)\b|node_modules/|"
    r"site-packages/|goroutine \d+ \[|panic: )")
CONTRACT_FAIL_RX = re.compile(
    r"(validation error|missing (\d+ )?required|required (positional |keyword )?argument|unexpected keyword|"
    r"TypeError|KeyError|AttributeError|NoneType|IndexError|invalid (argument|parameter|input|type|value)|"
    r"expected (a |an )?(str|int|float|bool|list|dict|string|integer|number|object|array)|is not of type|"
    r"is a required property|cannot be (empty|none|null)|ValueError)", re.I)
GENERIC_ERROR_RX = re.compile(
    r"^(error|failed|failure|exception|internal (server )?error|something went wrong|unknown error|"
    r"an error occurred|invalid( input| request)?|bad request|error executing tool [\w.\-]+)[\s.!:]*$", re.I)

_PATH_TOKENS = frozenset(["path", "file", "filename", "filepath", "dir", "directory", "folder", "document", "attachment", "template", "image", "log"])
_URL_TOKENS = frozenset(["url", "uri", "link", "href", "endpoint", "webhook", "site", "website", "feed"])
_SEARCH_TOKENS = frozenset(
    ["query", "search", "term", "keyword", "filter", "name", "title", "text", "q", "where", "tag", "category", "key", "user", "username", "order", "sort", "id", "email", "label"])
_SQL_PARAMS = frozenset(["sql", "query", "statement", "stmt"])
_CMD_PARAMS = frozenset(["command", "cmd", "code", "script", "expression", "expr", "shell", "bash"])
_COUNT_TOKENS = frozenset(["limit", "count", "max", "size", "top", "num", "results", "rows", "take", "length", "per"])
_ENV_PARAM_TOKENS = frozenset(["key", "name", "var", "variable", "env", "setting", "config", "option", "parameter"])
_DESTRUCTIVE = frozenset(
    ["delete", "remove", "drop", "write", "create", "update", "insert", "send", "post", "execute", "exec", "kill", "truncate", "overwrite", "modify", "edit", "push", "commit", "merge", "upload", "erase", "wipe", "destroy", "rename", "move", "deploy", "publish"])


def looks_like_contract_failure(text: str) -> bool:
    return bool(CONTRACT_FAIL_RX.search(text or ""))


def is_non_actionable(text: str) -> bool:
    t = (text or "").strip()
    return len(t) < 15 or bool(GENERIC_ERROR_RX.match(t))


def find_sql_error(text: str) -> str | None:
    m = SQL_ERROR_RX.search(text or "")
    return snippet(text, m.start(), m.end(), 60) if m else None


def find_trace(text: str) -> str | None:
    m = TRACE_RX.search(text or "")
    return snippet(text, m.start(), m.end(), 50) if m else None


def tool_is_probe_safe(tool: ToolInfo) -> tuple[bool, str]:
    toks = name_tokens(tool.name)
    if tool.destructive is True:
        return False, "destructive_hint=true"
    hit = next((t for t in toks if t in _DESTRUCTIVE), None)
    if hit:
        return False, f"name contains destructive verb '{hit}'"
    first = (tool.description or "").strip().split(" ", 1)[0].lower().strip(".,:;") if tool.description else ""
    if first in _DESTRUCTIVE:
        return False, f"description starts with destructive verb '{first}'"
    return True, ""


def _param_desc(tool: ToolInfo, pname: str) -> str:
    s = tool.properties.get(pname)
    return str(s.get("description", "")) if isinstance(s, dict) else ""


def is_pathlike(tool: ToolInfo, pname: str) -> bool:
    s = tool.properties.get(pname, {}) if isinstance(tool.properties.get(pname), dict) else {}
    if set(name_tokens(pname)) & _PATH_TOKENS or s.get("format") == "uri-reference":
        return True
    return bool(re.search(r"\b(file|path|directory|folder)\b", _param_desc(tool, pname), re.I))


def is_urllike(tool: ToolInfo, pname: str) -> bool:
    s = tool.properties.get(pname, {}) if isinstance(tool.properties.get(pname), dict) else {}
    if set(name_tokens(pname)) & _URL_TOKENS or s.get("format") in ("uri", "url"):
        return True
    return bool(re.search(r"\burl\b", _param_desc(tool, pname), re.I))


def is_sql_exec_param(tool: ToolInfo, pname: str) -> bool:
    if pname.lower() not in _SQL_PARAMS:
        return False
    hint = f"{tool.name} {tool.description}".lower()
    return pname.lower() in ("sql", "statement", "stmt") or bool(
        re.search(r"\b(sql|database|sqlite|postgres|mysql|select|table)\b", hint))


# ----------------------------------------------------------------------------- loopback canary listener
class CanaryListener:
    """A loopback HTTP server we own. If the target fetches a URL we point at it, that proves SSRF."""

    def __init__(self) -> None:
        self.token = f"mcpdoctor-ssrf-{secrets.token_hex(6)}"
        self.hits: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.hits.append(self.path)
                body = outer.token.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET  # noqa: N815
            do_HEAD = do_GET  # noqa: N815

            def log_message(self, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# ----------------------------------------------------------------------------- context
class BudgetExhausted(Exception):
    pass


@dataclass
class ProbeConfig:
    probe_all: bool = False
    max_calls: int = 700
    time_budget_s: float = 300.0
    slow_ms: float = 5000.0
    max_response_bytes: int = 200_000
    sandboxed: bool = False  # network-isolated: loopback callbacks from the server cannot reach us
    only: set[str] | None = None
    call_timeout: float = 20.0
    repeats: int = 3  # identical calls per tool: latency samples and time/count-triggered behaviour changes


SessionFactory = Callable[[], Awaitable["McpSession | None"]]


@dataclass
class ProbeContext:
    session: McpSession
    session_factory: SessionFactory
    isolation: Isolation | None
    tools: list[ToolInfo]
    config: ProbeConfig
    is_remote: bool = False
    findings: list[Finding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    records: list[CallRecord] = field(default_factory=list)
    purposes: list[str] = field(default_factory=list)
    evaluation: dict[str, Any] = field(default_factory=dict)
    restarts: int = 0
    skipped_tools: dict[str, str] = field(default_factory=dict)
    _t0: float = field(default_factory=time.monotonic)
    _seen: set[tuple[str, str | None, str]] = field(default_factory=set)

    # --------------------------------------------------------------- helpers
    def eligible(self) -> list[ToolInfo]:
        out = []
        for t in self.tools:
            if self.config.probe_all:
                out.append(t)
                continue
            ok, why = tool_is_probe_safe(t)
            if ok:
                out.append(t)
            else:
                self.skipped_tools[t.name] = why
        return out

    def add(self, finding: Finding, key: str | None = None) -> None:
        k = (finding.rule_id, finding.tool, key or finding.message)
        if k in self._seen:
            return
        self._seen.add(k)
        self.findings.append(finding)

    def cover(self, name: str, status: str, detail: str = "") -> None:
        self.coverage.append(Coverage(name, status, detail))

    async def call(self, tool: str, args: dict[str, Any], purpose: str) -> CallRecord:
        if len(self.records) >= self.config.max_calls:
            raise BudgetExhausted(f"call budget of {self.config.max_calls} reached")
        if time.monotonic() - self._t0 > self.config.time_budget_s:
            raise BudgetExhausted(f"time budget of {self.config.time_budget_s:.0f}s reached")
        if not self.session.alive:
            if self.restarts >= 3:
                rec = CallRecord(tool=tool, args=args, completed=False, exception="server stopped responding")
                self.records.append(rec)
                self.purposes.append(purpose)
                return rec
            await self.session.close()
            new = await self.session_factory()
            self.restarts += 1
            if new is None:
                raise BudgetExhausted("server could not be restarted after a crash")
            self.session = new
        rec = await self.session.call(tool, args, timeout=self.config.call_timeout)
        self.records.append(rec)
        self.purposes.append(purpose)
        if rec.timed_out:
            self.add(make_finding(
                "P002", f"Tool '{tool}' did not answer within {self.config.call_timeout:.0f}s ({purpose} probe).",
                tool=tool, evidence=_brief(args)), key=f"hang:{tool}")
        elif not rec.completed:
            self.add(make_finding(
                "P002", f"The server stopped responding while '{tool}' was being called ({purpose} probe): "
                f"{rec.exception}.", tool=tool, evidence=_brief(args),
                fix="Catch exceptions per tool call and return an MCP error result instead of exiting."),
                key=f"crash:{tool}:{purpose}")
        return rec


def _brief(args: dict[str, Any], limit: int = 160) -> str:
    try:
        text = json.dumps(args, default=str)
    except Exception:
        text = str(args)
    return text if len(text) <= limit else text[:limit] + f"... ({len(text)} chars)"


# ----------------------------------------------------------------------------- probes
async def probe_contract(ctx: ProbeContext) -> None:
    tested = passed = domain_errors = 0
    for t in ctx.eligible():
        rec = await ctx.call(t.name, minimal_args(t), "contract")
        tested += 1
        if not rec.completed:
            continue
        if rec.succeeded:
            passed += 1
            if t.output_schema:
                _check_output_schema(ctx, t, rec)
            for _ in range(max(0, ctx.config.repeats - 1)):
                again = await ctx.call(t.name, minimal_args(t), "repeat")
                if not again.succeeded:
                    break
        elif looks_like_contract_failure(rec.text):
            ctx.add(make_finding(
                "B001", f"Tool '{t.name}' rejected arguments built from its own schema: {rec.text[:160]!r}.",
                tool=t.name, evidence=_brief(rec.args), confidence="medium"))
        else:
            domain_errors += 1  # e.g. "not found": expected for synthetic inputs, not a schema fault
    ctx.evaluation["contract"] = {
        "tested": tested, "passed": passed, "domain_errors": domain_errors,
        "failed": sum(1 for f in ctx.findings if f.rule_id == "B001"),
        "skipped_tools": dict(ctx.skipped_tools),
    }
    detail = f"{tested} tool(s) called with schema-derived arguments (x{max(1, ctx.config.repeats)} each when they succeed)"
    if ctx.skipped_tools:
        detail += f"; {len(ctx.skipped_tools)} skipped as potentially destructive ({', '.join(list(ctx.skipped_tools)[:6])})"
    ctx.cover("contract", "ran", detail)


def _check_output_schema(ctx: ProbeContext, t: ToolInfo, rec: CallRecord) -> None:
    if rec.structured is None:
        ctx.add(make_finding(
            "B002", f"Tool '{t.name}' declares an output schema but returned no structured content.", tool=t.name))
        return
    try:
        jsonschema.validate(rec.structured, t.output_schema)
    except jsonschema.ValidationError as exc:
        ctx.add(make_finding(
            "B002", f"Tool '{t.name}' result violates its output schema: {exc.message[:160]}.", tool=t.name,
            evidence=_brief({"result": rec.structured})))
    except jsonschema.SchemaError:
        pass


async def probe_input_validation(ctx: ProbeContext) -> None:
    checked = 0
    for t in ctx.eligible():
        problems: list[str] = []
        for pname in list(t.properties)[:6]:
            typ = param_type(t, pname)
            if typ is None:
                continue
            bad: Any
            if typ in ("integer", "number"):
                bad = "mcpdoctor-not-a-number"
            elif typ == "boolean":
                bad = "mcpdoctor-not-a-bool"
            elif typ == "string":
                bad = {"mcpdoctor": "object"}
            elif typ == "array":
                bad = "mcpdoctor-not-an-array"
            elif typ == "object":
                bad = "mcpdoctor-not-an-object"
            else:
                continue
            args = minimal_args(t)
            args[pname] = bad
            rec = await ctx.call(t.name, args, "validation")
            checked += 1
            if rec.completed and not rec.is_error:
                problems.append(f"'{pname}' ({typ}) accepted {json.dumps(bad)}")
            elif rec.completed and rec.is_error and is_non_actionable(rec.text):
                pass  # reported by the B004 post-analysis
            if len(problems) >= 2:
                break
        if t.required:
            rec = await ctx.call(t.name, {}, "validation")
            checked += 1
            if rec.completed and not rec.is_error:
                problems.append(f"call without required parameter(s) {', '.join(t.required)} succeeded")
        if problems:
            ctx.add(make_finding("D009", f"Tool '{t.name}' ignores its schema: {'; '.join(problems)}.", tool=t.name))
    ctx.cover("input-validation", "ran", f"{checked} wrong-type / missing-argument call(s)")


async def probe_env_leak(ctx: ProbeContext) -> None:
    if ctx.isolation is None:
        ctx.cover("env-leak", "skipped", "no isolation environment (remote target): canary secrets cannot be planted")
        return
    calls = 0
    for t in ctx.eligible():
        for pname in t.properties:
            if set(name_tokens(pname)) & _ENV_PARAM_TOKENS and param_type(t, pname) == "string":
                for var in list(ctx.isolation.env_tokens)[:4]:
                    args = minimal_args(t)
                    args[pname] = var
                    await ctx.call(t.name, args, "env")
                    calls += 1
                break
    ctx.cover("env-leak", "ran", f"canary secrets planted in the server environment; {calls} targeted lookup call(s) "
              "plus every other response scanned")


async def probe_path_traversal(ctx: ProbeContext) -> None:
    payloads = ["../" * 8 + "etc/passwd", "/etc/passwd", "....//....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"]
    canary = None
    if ctx.isolation is not None:
        canary = ctx.isolation.server_canary_path or str(ctx.isolation.file_canary_path)
        payloads.append(canary)
    tested = 0
    for t in ctx.eligible():
        for pname in string_params(t):
            if not is_pathlike(t, pname):
                continue
            tested += 1
            for payload in payloads:
                args = minimal_args(t)
                args[pname] = payload
                rec = await ctx.call(t.name, args, "path")
                if not rec.completed:
                    break
                token = ctx.isolation.file_token if ctx.isolation else None
                hit = PASSWD_RX.search(rec.text) or (token is not None and token in rec.text)
                if hit:
                    what = "contents of /etc/passwd" if PASSWD_RX.search(rec.text) else "a planted canary file outside the working directory"
                    ctx.add(make_finding(
                        "D001", f"Tool '{t.name}' parameter '{pname}' returned {what} for payload {payload!r}.",
                        tool=t.name, evidence=f"payload={payload!r} -> {rec.text[:80]!r}"))
                    break
    ctx.cover("path-traversal", "ran" if tested else "not_applicable",
              f"{tested} path-like parameter(s) tested" if tested else "no path-like string parameters found")


async def probe_ssrf(ctx: ProbeContext) -> None:
    targets = [(t, p) for t in ctx.eligible() for p in string_params(t) if is_urllike(t, p)]
    if not targets:
        ctx.cover("ssrf", "not_applicable", "no URL-like parameters found")
        return
    if ctx.config.sandboxed:
        ctx.cover("ssrf", "skipped", "server runs in a no-network sandbox, so a loopback callback cannot be observed")
        return
    if ctx.is_remote:
        ctx.cover("ssrf", "skipped", "remote target: it would call back to its own loopback, not ours")
        return
    listener = CanaryListener()
    listener.start()
    try:
        port = listener.port
        variants = [
            ("plain loopback", f"http://127.0.0.1:{port}/mcpdoctor-ssrf"),
            ("localhost name", f"http://localhost:{port}/mcpdoctor-ssrf"),
            ("decimal IP bypass", f"http://2130706433:{port}/mcpdoctor-ssrf"),
            ("IPv4-mapped IPv6 bypass", f"http://[::ffff:127.0.0.1]:{port}/mcpdoctor-ssrf"),
        ]
        for t, pname in targets:
            hit_label = None
            for label, url in variants:
                before = len(listener.hits)
                args = minimal_args(t)
                args[pname] = url
                rec = await ctx.call(t.name, args, "ssrf")
                await asyncio.sleep(0.05)
                if len(listener.hits) > before or listener.token in rec.text:
                    hit_label = label
                    break
                if not rec.completed:
                    break
            if hit_label:
                ctx.add(make_finding(
                    "D002", f"Tool '{t.name}' parameter '{pname}' fetched a loopback URL ({hit_label}); "
                    "internal services and cloud metadata endpoints are reachable the same way.",
                    tool=t.name, evidence=f"loopback listener received {len(listener.hits)} request(s)"))
            # file:// scheme
            args = minimal_args(t)
            args[pname] = "file:///etc/passwd"
            rec = await ctx.call(t.name, args, "ssrf")
            if PASSWD_RX.search(rec.text):
                ctx.add(make_finding(
                    "D002", f"Tool '{t.name}' parameter '{pname}' reads local files through file:// URLs.",
                    tool=t.name, evidence=rec.text[:80]), key=f"file-scheme:{t.name}")
    finally:
        listener.stop()
    ctx.cover("ssrf", "ran", f"{len(targets)} URL-like parameter(s) tested against a loopback canary listener")


async def probe_sql(ctx: ProbeContext) -> None:
    searched = stacked = 0
    for t in ctx.eligible():
        for pname in string_params(t):
            if is_sql_exec_param(t, pname):
                stacked += 1
                rec = await ctx.call(t.name, {**minimal_args(t), pname: "SELECT 1; SELECT 2"}, "sql")
                if rec.completed and not rec.is_error and not re.search(r"(not allowed|only one|single statement)", rec.text, re.I):
                    ctx.add(make_finding(
                        "D004", f"Tool '{t.name}' executed two statements in one call ('SELECT 1; SELECT 2').",
                        tool=t.name, evidence=rec.text[:120]))
                if ctx.config.probe_all and (t.read_only is True or re.search(
                        r"read[- ]?only|only select", t.description or "", re.I)):
                    probe = "CREATE TABLE mcpdoctor_write_probe (x INTEGER)"
                    rec = await ctx.call(t.name, {**minimal_args(t), pname: probe}, "sql")
                    if rec.completed and not rec.is_error and not re.search(
                            r"(read[- ]?only|not allowed|denied|permission|forbidden)", rec.text, re.I):
                        ctx.add(make_finding(
                            "D005", f"Tool '{t.name}' claims to be read-only but executed a CREATE TABLE.",
                            tool=t.name, evidence=rec.text[:120]))
                        await ctx.call(t.name, {**minimal_args(t), pname: "DROP TABLE IF EXISTS mcpdoctor_write_probe"}, "sql")
            elif set(name_tokens(pname)) & _SEARCH_TOKENS and pname.lower() not in _CMD_PARAMS:
                searched += 1
                base = await ctx.call(t.name, minimal_args(t), "sql-baseline")
                if not base.completed or find_sql_error(base.text):
                    continue
                for payload in ("'", '"', "') OR ('1'='1"):
                    rec = await ctx.call(t.name, {**minimal_args(t), pname: payload}, "sql")
                    ev = find_sql_error(rec.text)
                    if ev:
                        ctx.add(make_finding(
                            "D003", f"Tool '{t.name}' parameter '{pname}' produced a database error for input "
                            f"{payload!r}: the value is concatenated into SQL.", tool=t.name, evidence=ev))
                        break
    if not ctx.config.probe_all:
        ctx.cover("sql-write-guard", "skipped", "write attempts (D005) only run with --probe-all, preferably in the sandbox")
    else:
        ctx.cover("sql-write-guard", "ran", "CREATE TABLE attempted against read-only SQL tools")
    ctx.cover("sql-injection", "ran" if (searched or stacked) else "not_applicable",
              f"{searched} search-style and {stacked} SQL-execution parameter(s) tested"
              if (searched or stacked) else "no SQL-related parameters found")


async def probe_command_injection(ctx: ProbeContext) -> None:
    payloads = [
        "; echo MCPDOCTOR_$((6*7))",
        "$(echo MCPDOCTOR_$((6*7)))",
        "`echo MCPDOCTOR_$((6*7))`",
        "| echo MCPDOCTOR_$((6*7))",
        "&& echo MCPDOCTOR_$((6*7))",
    ]
    tested = 0
    for t in ctx.eligible():
        for pname in string_params(t)[:5]:
            if pname.lower() in _CMD_PARAMS or is_sql_exec_param(t, pname):
                continue  # execution is the declared purpose; reported by S005 instead
            tested += 1
            base = str(sample_value(t.properties.get(pname, {}), pname, t.input_schema))
            for payload in payloads:
                rec = await ctx.call(t.name, {**minimal_args(t), pname: base + payload}, "cmd")
                if not rec.completed:
                    break
                if CMD_MARKER_RX.search(rec.text):
                    ctx.add(make_finding(
                        "D006", f"Tool '{t.name}' parameter '{pname}' executed shell syntax: the computed marker "
                        f"MCPDOCTOR_42 appeared in the output for payload {payload!r}.", tool=t.name,
                        evidence=f"{payload!r} -> {rec.text[:100]!r}"))
                    break
    ctx.cover("command-injection", "ran" if tested else "not_applicable",
              f"{tested} string parameter(s) tested with shell-metacharacter markers (POSIX shells)"
              if tested else "no string parameters found")


async def probe_unbounded(ctx: ProbeContext) -> None:
    tested = 0
    for t in ctx.eligible():
        for pname in t.properties:
            if param_type(t, pname) != "integer" or not (set(name_tokens(pname)) & _COUNT_TOKENS):
                continue
            schema = t.properties[pname]
            cap = schema.get("maximum") if isinstance(schema, dict) else None
            value = 100_000 if cap is None else int(cap)
            tested += 1
            rec = await ctx.call(t.name, {**minimal_args(t), pname: value}, "unbounded")
            if rec.completed and rec.size_bytes > ctx.config.max_response_bytes:
                ctx.add(make_finding(
                    "D010", f"Tool '{t.name}' returned {rec.size_bytes:,} bytes for {pname}={value:,} "
                    f"(limit {ctx.config.max_response_bytes:,}).", tool=t.name,
                    evidence=f"{pname}={value}, size={rec.size_bytes}"))
            break
    ctx.cover("unbounded-output", "ran" if tested else "not_applicable",
              f"{tested} limit-style parameter(s) set to large values" if tested else "no limit/count parameters found")


async def probe_drift(ctx: ProbeContext) -> None:
    if not ctx.session.alive:
        ctx.cover("definition-drift", "skipped", "server was not alive at the end of the run")
        return
    try:
        after = await ctx.session.list_tools()
    except Exception as exc:
        ctx.cover("definition-drift", "skipped", f"could not re-list tools: {type(exc).__name__}")
        return
    before = {t.name: t.fingerprint() for t in ctx.tools}
    now = {t.name: t.fingerprint() for t in after}
    changed = sorted(n for n in before if n in now and before[n] != now[n])
    added = sorted(set(now) - set(before))
    removed = sorted(set(before) - set(now))
    if changed or added or removed:
        parts = []
        if changed:
            parts.append(f"changed: {', '.join(changed)}")
        if added:
            parts.append(f"added: {', '.join(added)}")
        if removed:
            parts.append(f"removed: {', '.join(removed)}")
        ctx.add(make_finding(
            "D011", f"Tool definitions differ after {len(ctx.records)} calls ({'; '.join(parts)}).",
            tool=(changed or added or removed)[0]))
        # The new text is what a model reads from now on, so scan it as well.
        from mcpdoctor.security_static import scan_metadata

        new_tools = [t for t in after if t.name in set(changed) | set(added)]
        for f in scan_metadata(new_tools):
            f.message = f"[after the definition changed] {f.message}"
            ctx.add(f)
    ctx.cover("definition-drift", "ran", f"tool list re-read after {len(ctx.records)} calls and compared by hash")


async def probe_robustness(ctx: ProbeContext) -> None:
    tested = 0
    for t in ctx.eligible():
        for pname in string_params(t)[:3]:
            for label, value in (("65,536-character string", "A" * 65536), ("NUL byte", "a\x00b"), ("empty string", "")):
                tested += 1
                rec = await ctx.call(t.name, {**minimal_args(t), pname: value}, "robustness")
                if not rec.completed:
                    crash = next((f for f in reversed(ctx.findings)
                                  if f.rule_id == "P002" and f.tool == t.name), None)
                    if crash is not None and "Trigger:" not in crash.message:
                        crash.message += f" Trigger: {label} in parameter '{pname}'."
                    break
    ctx.cover("robustness", "ran", f"{tested} unusual-input call(s) (long string, NUL byte, empty string)")


# ----------------------------------------------------------------------------- post analysis
def analyze_records(ctx: ProbeContext) -> None:
    """Scan everything the server ever said for leaks, stack traces, slowness and useless errors."""
    env_map = {v: k for k, v in (ctx.isolation.env_tokens.items() if ctx.isolation else [])}
    file_token = ctx.isolation.file_token if ctx.isolation else None
    latencies: dict[str, list[float]] = {}
    useless: dict[str, str] = {}

    for rec, purpose in zip(ctx.records, ctx.purposes, strict=False):
        blob = rec.text
        if rec.structured is not None:
            try:
                blob += "\n" + json.dumps(rec.structured, default=str)
            except Exception:
                blob += "\n" + str(rec.structured)
        for token, var in env_map.items():
            if token in blob:
                ctx.add(make_finding(
                    "D008", f"Tool '{rec.tool}' returned the value of environment variable {var} "
                    f"(a planted canary) during the '{purpose}' step.", tool=rec.tool,
                    evidence=f"{var}=<canary> found in output"), key=f"env:{rec.tool}")
        if file_token and file_token in blob and purpose != "path":
            ctx.add(make_finding(
                "D001", f"Tool '{rec.tool}' returned the contents of a canary file placed in the home directory.",
                tool=rec.tool, evidence="canary token found in output"), key=f"canary:{rec.tool}")
        trace = find_trace(blob)
        if trace and rec.completed:
            ctx.add(make_finding(
                "D007", f"Tool '{rec.tool}' output contains internal details (stack trace or file path).",
                tool=rec.tool, evidence=trace), key=f"trace:{rec.tool}")
        if rec.completed and not rec.timed_out and purpose not in ("robustness", "unbounded"):
            latencies.setdefault(rec.tool, []).append(rec.latency_ms)
        if rec.completed and rec.is_error and is_non_actionable(rec.text) and rec.tool not in useless:
            useless[rec.tool] = rec.text.strip()
        if rec.completed and rec.size_bytes > ctx.config.max_response_bytes and purpose != "unbounded":
            ctx.add(make_finding(
                "D010", f"Tool '{rec.tool}' returned {rec.size_bytes:,} bytes in a single response.",
                tool=rec.tool, evidence=f"size={rec.size_bytes}"), key=f"big:{rec.tool}")

    for tool, text in useless.items():
        ctx.add(make_finding(
            "B004", f"Tool '{tool}' returned an error an agent cannot act on: {text!r}.", tool=tool, evidence=text))
    slow_ms = ctx.config.slow_ms
    for tool, samples in latencies.items():
        p95 = _p95(samples)
        if samples and p95 > slow_ms:
            ctx.add(make_finding(
                "B003", f"Tool '{tool}' p95 latency is {p95:,.0f} ms over {len(samples)} call{'s' if len(samples) != 1 else ''} "
                f"(limit {slow_ms:,.0f} ms).",
                tool=tool, evidence=f"samples_ms={[round(s) for s in samples[:6]]}"))
    ctx.evaluation["latency_ms"] = {
        tool: {"calls": len(s), "p50": round(statistics.median(s)), "p95": round(_p95(s))}
        for tool, s in sorted(latencies.items())
    }
    ctx.evaluation["calls_made"] = len(ctx.records)
    ctx.evaluation["server_restarts"] = ctx.restarts


def _p95(samples: list[float]) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    idx = min(len(s) - 1, max(0, int(round(0.95 * (len(s) - 1)))))
    return s[idx]


PROBES: list[tuple[str, Callable[[ProbeContext], Awaitable[None]]]] = [
    ("contract", probe_contract),
    ("input-validation", probe_input_validation),
    ("env-leak", probe_env_leak),
    ("path-traversal", probe_path_traversal),
    ("sql", probe_sql),
    ("command-injection", probe_command_injection),
    ("ssrf", probe_ssrf),
    ("unbounded-output", probe_unbounded),
    ("definition-drift", probe_drift),
    ("robustness", probe_robustness),
]


async def run_probes(ctx: ProbeContext) -> None:
    for name, fn in PROBES:
        if ctx.config.only is not None and name not in ctx.config.only:
            ctx.cover(name, "skipped", "not selected (--probes)")
            continue
        if not ctx.session.alive and ctx.restarts >= 3:
            ctx.cover(name, "skipped", "server kept crashing; probing stopped")
            continue
        try:
            await fn(ctx)
        except BudgetExhausted as exc:
            ctx.cover(name, "skipped", f"stopped: {exc}")
            for later, _ in PROBES[[n for n, _ in PROBES].index(name) + 1:]:
                ctx.cover(later, "skipped", f"stopped: {exc}")
            break
    analyze_records(ctx)


_ = Severity  # re-exported for type checkers
