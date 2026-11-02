"""A thin, defensive wrapper around the MCP SDK client.

Everything MCPDoctor does to a server goes through :class:`McpSession`. It never raises for a *tool-level*
problem - failures become :class:`~mcpdoctor.models.CallRecord` values - so that one misbehaving tool cannot
abort the scan, and so that crashes and hangs are observed and reported instead of propagated.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
import time
from contextlib import AsyncExitStack
from typing import Any

from mcp import Client, MCPError, StdioServerParameters
from mcp.client.session import CONNECTION_CLOSED
from mcp.client.stdio import stdio_client

from mcpdoctor.models import CallRecord, ServerIdentity, ToolInfo
from mcpdoctor.target import Isolation, Target

DEFAULT_CALL_TIMEOUT = 20.0
DEFAULT_INIT_TIMEOUT = 45.0


class StartupError(RuntimeError):
    def __init__(self, message: str, stderr_tail: str = ""):
        super().__init__(message)
        self.stderr_tail = stderr_tail


class _StdioTransport:
    """Adapter so we can hand the SDK a stdio transport whose stderr we capture."""

    def __init__(self, params: StdioServerParameters, errlog: Any):
        self._params = params
        self._errlog = errlog
        self._cm: Any = None

    async def __aenter__(self) -> Any:
        self._cm = stdio_client(self._params, errlog=self._errlog)
        return await self._cm.__aenter__()

    async def __aexit__(self, *exc: Any) -> Any:
        return await self._cm.__aexit__(*exc)


class _HttpTransport:
    def __init__(self, url: str, headers: dict[str, str]):
        self._url = url
        self._headers = headers
        self._http: Any = None
        self._cm: Any = None

    async def __aenter__(self) -> Any:
        import httpx2  # installed as a dependency of the mcp SDK
        from mcp.client.streamable_http import streamable_http_client

        self._http = httpx2.AsyncClient(headers=self._headers, timeout=30.0, follow_redirects=True)
        self._cm = streamable_http_client(self._url, http_client=self._http)
        return await self._cm.__aenter__()

    async def __aexit__(self, *exc: Any) -> Any:
        try:
            return await self._cm.__aexit__(*exc)
        finally:
            if self._http is not None:
                await self._http.aclose()


def _tool_from_sdk(t: Any) -> ToolInfo:
    ann: dict[str, Any] = {}
    if getattr(t, "annotations", None) is not None:
        ann = t.annotations.model_dump(exclude_none=True)
    return ToolInfo(
        name=t.name,
        description=t.description or "",
        input_schema=dict(t.input_schema or {}),
        output_schema=dict(t.output_schema) if getattr(t, "output_schema", None) else None,
        title=getattr(t, "title", None),
        annotations=ann,
    )


def _flatten_content(content: Any) -> str:
    parts: list[str] = []
    for block in content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
        else:
            kind = getattr(block, "type", type(block).__name__)
            parts.append(f"[{kind} content]")
    return "\n".join(parts)


class McpSession:
    def __init__(self, target: Target, isolation: Isolation | None = None, *,
                 call_timeout: float = DEFAULT_CALL_TIMEOUT, init_timeout: float = DEFAULT_INIT_TIMEOUT):
        self.target = target
        self.isolation = isolation
        self.call_timeout = call_timeout
        self.init_timeout = init_timeout
        self.identity = ServerIdentity()
        self.startup_ms = 0.0
        self.alive = False
        self.crashed = False
        self.hung_calls = 0
        self.calls_made = 0
        self._stack = AsyncExitStack()
        self._client: Client | None = None
        self._errfile = tempfile.TemporaryFile(mode="w+")  # noqa: SIM115 - closed in close()
        self._consecutive_timeouts = 0

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        t0 = time.perf_counter()
        transport: Any
        if self.target.kind == "stdio":
            if self.target.sandboxed:
                env, cwd = dict(self.target.env), self.target.cwd  # the docker client keeps its normal HOME
            else:
                env = dict(self.isolation.env) if self.isolation else {}
                env.update(self.target.env)
                cwd = self.target.cwd or (str(self.isolation.workdir) if self.isolation else None)
            params = StdioServerParameters(command=self.target.command[0], args=self.target.command[1:],
                                           env=env, cwd=cwd)
            transport = _StdioTransport(params, self._errfile)
        else:
            assert self.target.url is not None
            transport = _HttpTransport(self.target.url, self.target.headers)
        try:
            async with asyncio.timeout(self.init_timeout):
                client = Client(transport)
                self._client = await self._stack.enter_async_context(client)
        except BaseException as exc:
            with contextlib.suppress(BaseException):
                async with asyncio.timeout(5):
                    await self._stack.aclose()
            elapsed = time.perf_counter() - t0
            timed_out = isinstance(exc, TimeoutError) or elapsed >= self.init_timeout * 0.95
            if isinstance(exc, KeyboardInterrupt | SystemExit):
                raise
            if timed_out:
                detail = (f"no MCP handshake within {self.init_timeout:.0f}s - the process may not be an MCP "
                          "server, may be waiting for input, or may be printing non-protocol text to stdout")
            else:
                detail = _root_cause(exc)
            raise StartupError(f"could not complete the MCP handshake: {detail}", self.stderr_tail()) from exc
        self.startup_ms = (time.perf_counter() - t0) * 1000
        self.alive = True
        info = getattr(self._client, "server_info", None)
        self.identity = ServerIdentity(
            name=getattr(info, "name", None) or "unknown",
            version=getattr(info, "version", None) or "",
            protocol_version=str(getattr(self._client, "protocol_version", "") or ""),
            instructions=getattr(self._client, "instructions", None),
        )

    async def close(self) -> None:
        try:
            with contextlib.suppress(BaseException):
                async with asyncio.timeout(10):
                    await self._stack.aclose()
        finally:
            with contextlib.suppress(Exception):
                self._errfile.close()
            self.alive = False

    def stderr_tail(self, limit: int = 2500) -> str:
        try:
            self._errfile.flush()
            self._errfile.seek(0)
            data = self._errfile.read()
            self._errfile.seek(0, 2)
            return data[-limit:]
        except Exception:
            return ""

    # ------------------------------------------------------------------ operations
    async def list_tools(self) -> list[ToolInfo]:
        assert self._client is not None
        tools: list[ToolInfo] = []
        cursor: str | None = None
        for _ in range(50):  # pagination guard
            result = await asyncio.wait_for(self._client.list_tools(cursor=cursor), self.init_timeout)
            tools.extend(_tool_from_sdk(t) for t in result.tools)
            cursor = getattr(result, "next_cursor", None)
            if not cursor:
                break
        return tools

    async def call(self, tool: str, args: dict[str, Any] | None = None,
                   timeout: float | None = None) -> CallRecord:
        args = args or {}
        timeout = timeout or self.call_timeout
        rec = CallRecord(tool=tool, args=args, completed=False)
        if not self.alive or self._client is None:
            rec.exception = "session is not alive"
            return rec
        self.calls_made += 1
        t0 = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self._client.call_tool(tool, args, read_timeout_seconds=timeout), timeout + 2.0
            )
        except TimeoutError:
            rec.timed_out = True
            rec.exception = f"no response within {timeout:.0f}s"
            self.hung_calls += 1
            self._consecutive_timeouts += 1
            if self._consecutive_timeouts >= 2:
                self.alive = False
        except MCPError as exc:
            if getattr(exc, "code", None) == CONNECTION_CLOSED:
                # The server process went away mid-call: that is a crash, not an error reply.
                rec.exception = "connection closed by the server (the process exited)"
                self.alive = False
                self.crashed = True
            else:
                rec.completed = True
                rec.is_error = True
                rec.text = str(getattr(exc, "message", None) or exc)
                self._consecutive_timeouts = 0
        except Exception as exc:
            rec.exception = _root_cause(exc)
            self.alive = False
            self.crashed = True
        else:
            rec.completed = True
            rec.is_error = bool(getattr(result, "is_error", False))
            rec.text = _flatten_content(result.content)
            rec.structured = getattr(result, "structured_content", None)
            rec.size_bytes = len(rec.text.encode("utf-8", "replace"))
            self._consecutive_timeouts = 0
        rec.latency_ms = (time.perf_counter() - t0) * 1000
        return rec


def _root_cause(exc: BaseException) -> str:
    """Unwrap exception groups produced by anyio task groups into one readable line."""
    seen = 0
    while seen < 8:
        seen += 1
        inner = getattr(exc, "exceptions", None)
        if inner:
            exc = inner[0]
            continue
        if exc.__cause__ is not None and not str(exc):
            exc = exc.__cause__
            continue
        break
    text = str(exc).strip() or type(exc).__name__
    return f"{type(exc).__name__}: {text}"[:300]
