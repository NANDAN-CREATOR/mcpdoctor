"""DELIBERATELY VULNERABLE: do not use. Test fixture for MCPDoctor's dynamic probes.

Planted defects: D001 (path traversal), D002 (SSRF incl. file://), D007 (stack traces in errors).
"""

import traceback
import urllib.request

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

mcp = MCPServer("file-helper")
RO = ToolAnnotations(read_only_hint=True, destructive_hint=False)


@mcp.tool(annotations=RO)
def read_file(path: str) -> str:
    """Read a text file from disk and return its contents. Use when the user asks for the contents of a file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:  # no confinement at all
            return fh.read()[:4000]
    except Exception:
        raise ToolError(traceback.format_exc()) from None  # leaks internals to the caller


@mcp.tool(annotations=RO)
def fetch(url: str) -> str:
    """Download a web page and return its text. Use when the user gives a URL and wants to read the page."""
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # follows any scheme/host: SSRF + file://
            return resp.read(4000).decode("utf-8", "replace")
    except Exception:
        raise ToolError(traceback.format_exc()) from None


if __name__ == "__main__":
    mcp.run()
