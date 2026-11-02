"""Transport-level checks for remote (Streamable HTTP) MCP servers."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from mcpdoctor import __version__
from mcpdoctor.models import Coverage, Finding, Severity
from mcpdoctor.rules import make_finding
from mcpdoctor.target import Target

_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcpdoctor", "version": __version__},
    },
}
_AUTH_HEADERS = ("authorization", "x-api-key", "api-key", "x-auth-token", "cookie", "proxy-authorization")


def _post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> tuple[int | None, str]:
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **headers}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _accepted(status: int | None, body: str) -> bool:
    return status == 200 and '"result"' in body


def check_http_target(target: Target, timeout: float = 8.0) -> tuple[list[Finding], list[Coverage]]:
    assert target.url is not None
    findings: list[Finding] = []
    cover: list[Coverage] = []

    if target.url.lower().startswith("http://") and target.is_remote:
        findings.append(make_finding(
            "S007", f"{target.url} is a remote server reached over plain HTTP.", evidence=target.url))
        cover.append(Coverage("transport-security", "ran", "cleartext HTTP to a remote host"))
    else:
        cover.append(Coverage("transport-security", "ran", "no cleartext remote transport"))

    # S008 - does the endpoint answer without credentials?
    public_headers = {k: v for k, v in target.headers.items() if k.lower() not in _AUTH_HEADERS}
    status, body = _post(target.url, _INIT, public_headers, timeout)
    if status is None:
        cover.append(Coverage("authentication", "skipped", f"could not reach endpoint: {body[:100]}"))
    elif _accepted(status, body):
        sev = Severity.HIGH if target.is_remote else Severity.MEDIUM
        findings.append(make_finding(
            "S008", f"{target.url} completed an MCP initialize request without any credentials "
            f"(HTTP {status}).", severity=sev, evidence=body[:160].replace("\n", " ")))
        cover.append(Coverage("authentication", "ran", "endpoint accepts anonymous requests"))
    else:
        cover.append(Coverage("authentication", "ran", f"anonymous request refused (HTTP {status})"))

    # S009 - does the endpoint accept a request from a foreign web origin?
    status2, body2 = _post(target.url, _INIT, {**target.headers, "Origin": "http://evil.mcpdoctor.invalid"}, timeout)
    if status2 is None:
        cover.append(Coverage("origin-validation", "skipped", "endpoint not reachable"))
    elif _accepted(status2, body2):
        findings.append(make_finding(
            "S009", f"{target.url} accepted a request with Origin: http://evil.mcpdoctor.invalid (HTTP {status2}).",
            evidence=body2[:160].replace("\n", " ")))
        cover.append(Coverage("origin-validation", "ran", "foreign Origin accepted"))
    else:
        cover.append(Coverage("origin-validation", "ran", f"foreign Origin refused or inconclusive (HTTP {status2})"))
    return findings, cover
