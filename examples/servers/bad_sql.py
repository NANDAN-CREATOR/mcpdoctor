"""DELIBERATELY VULNERABLE: do not use. Test fixture for MCPDoctor's SQL probes.

Planted defects: D003 (string-built SQL leaks errors), D004 (stacked statements), D005 (read-only claim is false),
S005 (raw SQL surface).
"""

import sqlite3
import threading

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

mcp = MCPServer("user-db")
RO = ToolAnnotations(read_only_hint=True, destructive_hint=False)

_db = sqlite3.connect(":memory:", check_same_thread=False)
_lock = threading.Lock()
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
_db.executemany("INSERT INTO users (name, email) VALUES (?, ?)", [("alice", "a@example.com"), ("bob", "b@example.com")])


@mcp.tool(annotations=RO)
def search_users(name: str) -> str:
    """Find users whose name contains the given text and return their ids and names. Use when the user asks who
    someone is."""
    sql = f"SELECT id, name FROM users WHERE name LIKE '%{name}%'"  # injectable
    try:
        with _lock:
            return str(_db.execute(sql).fetchall())
    except sqlite3.Error as exc:
        raise ToolError(f"Database error ({type(exc).__name__}): {exc}") from None


@mcp.tool(annotations=RO)
def run_query(sql: str) -> str:
    """Run a read-only SQL query against the user database and return the rows. Use for analytics questions."""
    try:
        with _lock:
            _db.executescript(sql)  # runs *every* statement, including writes
        return "OK"
    except sqlite3.Error as exc:
        raise ToolError(f"Database error ({type(exc).__name__}): {exc}") from None


if __name__ == "__main__":
    mcp.run()
