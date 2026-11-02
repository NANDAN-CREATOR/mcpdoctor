"""Community submissions: parse the GitHub issue form, validate the address, enforce daily limits, store results.

Everything here is pure logic (no network except DNS) so it can be unit-tested. The GitHub-facing glue lives in
``scripts/submission.py`` and the workflow ``.github/workflows/scan-request.yml``.

Threat model: the server address is typed by an anonymous person and the scan runs on a GitHub runner. So we only
accept public https addresses, never IP literals, never private/loopback/link-local targets, never credentials, and
the scan job runs with a read-only token.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcpdoctor.leaderboard import row_from_report, slugify
from mcpdoctor.models import Report
from mcpdoctor.report import render_html, render_json, score_badge

DAILY_LIMIT = 5      # servers tested per UTC day, across everybody
PER_USER_LIMIT = 2   # per GitHub user per UTC day (the repository owner is exempt)
MAX_URL_LENGTH = 300
INDEX_MAX_ROWS = 500


class SubmissionError(ValueError):
    """The request cannot be accepted; the message is shown to the submitter."""


# ------------------------------------------------------------------------------------------ issue form
def parse_issue_form(body: str) -> dict[str, str]:
    """GitHub renders issue forms as '### Label' sections. Return {label: text}."""
    sections: dict[str, str] = {}
    for m in re.finditer(r"^### (.+?)\s*\n(.*?)(?=^### |\Z)", body or "", re.S | re.M):
        sections[m.group(1).strip()] = m.group(2).strip()
    return sections


def effective_user(login: str, body: str, owner: str) -> str:
    """Web submissions are opened by the relay using the owner's token, so the issue author is the owner for everybody.
    Their anonymous id is in the body. Only honoured when the author is the owner, so nobody else can fake it."""
    if login.lower() == owner.lower():
        who = parse_issue_form(body).get("Submitter", "").strip()
        if re.fullmatch(r"web-[0-9a-f]{12}", who):
            return who
    return login


def read_request(body: str) -> tuple[str, bool]:
    form = parse_issue_form(body)
    url = form.get("MCP server address", "").strip()
    consent = form.get("Permission", "")
    return url, bool(re.search(r"^- \[[xX]\]", consent, re.M))


# ------------------------------------------------------------------------------------------ address checks
def _is_public(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text.split("%")[0]).is_global
    except ValueError:
        return False


Resolver = Callable[[str, int], list[tuple[Any, ...]]]


def _default_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def validate_server_url(raw: str, resolver: Resolver = _default_resolver) -> str:
    url = (raw or "").strip()
    if not url:
        raise SubmissionError("No server address was found in the form.")
    if len(url) > MAX_URL_LENGTH or re.search(r"\s", url) or not url.isascii():
        raise SubmissionError("The address must be a single plain URL (ASCII, no spaces, under 300 characters).")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SubmissionError("Only https:// addresses can be tested here (plain http is not allowed).")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise SubmissionError("The address must not contain a username or password. Servers that need a login "
                              "cannot be tested here; run MCPDoctor yourself instead.")
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        raise SubmissionError("The address needs a public domain name.")
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost", ".lan", ".home")):
        raise SubmissionError("Local and internal addresses cannot be tested here.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SubmissionError("Please use a domain name, not a raw IP address.")
    if parsed.port not in (None, 443):
        raise SubmissionError("Only the standard https port (443) is allowed.")
    if parsed.query or parsed.fragment:
        raise SubmissionError("The address must not contain a query string or fragment (no tokens or keys).")
    try:
        infos = resolver(host, 443)
    except OSError as exc:
        raise SubmissionError(f"Could not find that domain name ({host}).") from exc
    addresses = {str(info[4][0]) for info in infos}
    if not addresses or not all(_is_public(a) for a in addresses):
        raise SubmissionError("That address points to a private or non-public network, so it cannot be tested.")
    return url


def slug_for(url: str) -> str:
    parsed = urlparse(url)
    digest = hashlib.sha1(url.encode()).hexdigest()[:6]  # noqa: S324 - an id, not security
    return f"c-{slugify(parsed.hostname or 'server')[:40]}-{digest}"


# ------------------------------------------------------------------------------------------ limits
def utc_midnight(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


def decide(accepted_today: list[dict[str, str]], user: str, owner: str) -> Decision:
    """``accepted_today``: issues already accepted since 00:00 UTC, each {"user": login}."""
    if len(accepted_today) >= DAILY_LIMIT:
        return Decision(False, f"The daily limit of {DAILY_LIMIT} tests has been reached. The counter resets at "
                               "00:00 UTC. Please open a new request tomorrow.")
    mine = sum(1 for a in accepted_today if a.get("user", "").lower() == user.lower())
    if user.lower() != owner.lower() and mine >= PER_USER_LIMIT:
        return Decision(False, f"You have already used your {PER_USER_LIMIT} tests for today. Please try again "
                               "after 00:00 UTC.")
    return Decision(True)


# ------------------------------------------------------------------------------------------ results
def write_outputs(report: Report, url: str, out_dir: Path) -> dict[str, Any]:
    """Write the report files and the leaderboard row for one scanned submission."""
    slug = slug_for(url)
    parsed = urlparse(url)
    report.target = f"{parsed.hostname}{parsed.path.rstrip('/')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{slug}.html").write_text(render_html(report))
    (out_dir / f"{slug}.json").write_text(render_json(report))
    (out_dir / f"{slug}.svg").write_text(score_badge(report))
    row = row_from_report(report, kind="community", slug=slug, subtitle="community submission")
    (out_dir / "row.json").write_text(json.dumps(row, indent=2))
    return row


def merge_index(data_dir: Path, row: dict[str, Any]) -> None:
    """Add or replace a row in ``index.json`` (same slug = same address = replaced). Keeps the newest rows."""
    path = data_dir / "index.json"
    try:
        rows = json.loads(path.read_text()) if path.exists() else []
    except ValueError:
        rows = []
    rows = [r for r in rows if isinstance(r, dict) and r.get("slug") != row["slug"]]
    rows.append(row)
    rows = rows[-INDEX_MAX_ROWS:]
    path.write_text(json.dumps(rows, indent=2) + "\n")
