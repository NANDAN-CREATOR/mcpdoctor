"""DELIBERATELY FRAGILE: do not use. Test fixture for the robustness probe (P002).

The server process exits when a NUL byte reaches parse_text, taking every other tool offline with it.
"""

import os

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

mcp = MCPServer("fragile-parser")
RO = ToolAnnotations(read_only_hint=True, destructive_hint=False)


@mcp.tool(annotations=RO)
def parse_text(text: str) -> str:
    """Parse the supplied text and return the number of words it contains. Use when the user wants a word count."""
    if "\x00" in text:
        os._exit(3)  # hard exit, no cleanup, no error response
    return str(len(text.split()))


@mcp.tool(annotations=RO)
def echo_text(message: str) -> str:
    """Return the supplied message unchanged. Use when the user wants to test connectivity with the server."""
    return message


if __name__ == "__main__":
    mcp.run()
