"""A well-behaved MCP server: MCPDoctor's "known good" reference.

It deliberately follows every practice MCPDoctor checks for: precise descriptions with when-to-use guidance,
described and constrained parameters, behaviour annotations, output schemas, parameterised SQL, path
confinement, SSRF protection and actionable error messages. The test-suite requires this server to produce
no finding of severity MEDIUM or above (a false-positive guard).
"""

import ipaddress
import os
import socket
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

mcp = MCPServer("notes-demo", instructions="Search notes, read note files and fetch public web pages.")

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
READ_ONLY_OPEN = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                                 open_world_hint=True)

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db_lock = threading.Lock()
_db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
_db.executemany("INSERT INTO notes (title, body) VALUES (?, ?)", [
    ("Onboarding", "Welcome checklist for new engineers: laptop, accounts, first-week goals."),
    ("Release plan", "Ship the beta on Friday after the security review is complete."),
    ("Ideas", "A weekly newsletter about reliable data pipelines."),
])


class Note(BaseModel):
    id: int
    title: str
    body: str


@mcp.tool(annotations=READ_ONLY)
def add_numbers(
    a: Annotated[float, Field(description="First number to add, any finite value such as 2.5.")],
    b: Annotated[float, Field(description="Second number to add, any finite value such as 4.")],
) -> float:
    """Add two numbers and return their sum. Use for simple arithmetic only; do not use it to look up notes or files."""
    return a + b


@mcp.tool(annotations=READ_ONLY)
def search_notes(
    term: Annotated[str, Field(description="Keyword to look for in note titles and bodies, 1-100 characters, "
                                           "for example 'release'.", min_length=1, max_length=100)],
    limit: Annotated[int, Field(description="Maximum number of notes to return, from 1 to 50.", ge=1, le=50)] = 10,
) -> list[Note]:
    """Search saved notes by keyword and return the matching notes. Use when the user asks about the content of their
    notes; do not use it to read files from disk (use read_note_file) or for arithmetic."""
    like = f"%{term}%"
    with _db_lock:
        rows = _db.execute(
            "SELECT id, title, body FROM notes WHERE title LIKE ? OR body LIKE ? ORDER BY id LIMIT ?",
            (like, like, limit)).fetchall()
    return [Note(id=r[0], title=r[1], body=r[2]) for r in rows]


@mcp.tool(annotations=READ_ONLY)
def read_note_file(
    filename: Annotated[str, Field(
        description="Name of a text file in the notes directory, such as 'allowed.txt'. Only letters, digits, '_', "
                    "'-' and '.' are allowed; folders are not supported.",
        pattern=r"^[A-Za-z0-9_.-]{1,80}$")],
) -> str:
    """Read a small text file from the notes directory and return its contents. Use when the user names a specific
    notes file; do not use it for files elsewhere on the system."""
    base = Path(os.getcwd()).resolve()
    target = (base / filename).resolve()
    if base not in target.parents:
        raise ToolError(f"{filename!r} is outside the notes directory. Use a plain file name such as 'allowed.txt'.")
    if not target.is_file():
        raise ToolError(f"No file named {filename!r} exists in the notes directory. Try 'allowed.txt'.")
    return target.read_text(errors="replace")[:20000]


def _refuse_non_public(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        raise ToolError("Only absolute http:// or https:// URLs are supported.")
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ToolError(f"Could not resolve the host {host!r}; check the spelling of the URL.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped  # type: ignore[assignment]
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
                or ip.is_unspecified):
            raise ToolError("Refusing to fetch a URL that points to a private or local network address.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


@mcp.tool(annotations=READ_ONLY_OPEN)
def fetch_page(
    url: Annotated[str, Field(description="Absolute http(s) URL of a public web page, for example "
                                          "'https://example.com/'.", pattern=r"^https?://", max_length=2000,
                              json_schema_extra={"format": "uri"})],
) -> str:
    """Fetch a public web page and return up to 5,000 characters of its text. Use when the user supplies a public
    URL to read; do not use it for local or private network addresses (they are refused)."""
    _refuse_non_public(url)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "notes-demo"}), timeout=3) as resp:
            return resp.read(5000).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ToolError(f"Could not fetch {url}: {type(exc).__name__}. The site may be unreachable.") from exc


@mcp.tool(annotations=READ_ONLY)
def get_server_time() -> str:
    """Return the current UTC date and time in ISO 8601 format. Use when the user asks what time or date it is; do
    not use it for time-zone conversion."""
    return datetime.now(UTC).isoformat(timespec="seconds")


if __name__ == "__main__":
    mcp.run()
