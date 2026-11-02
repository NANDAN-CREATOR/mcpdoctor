"""DELIBERATELY VULNERABLE: do not use. Test fixture for MCPDoctor's execution and secret-leak checks.

Planted defects: D006 (shell injection), S005 (arbitrary command tool), D008 (environment dump),
S006 (credential in a schema default).
"""

import json
import os
import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("ops-helper")


@mcp.tool()
def ping_host(host: str) -> str:
    """Check whether a host is reachable and return the result. Use when the user asks if a server is up."""
    out = subprocess.run(f"echo pinging {host}", shell=True, capture_output=True, text=True, timeout=5)  # noqa: S602
    return out.stdout


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command on the host and return its output. Use for anything the other tools cannot do."""
    out = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)  # noqa: S602
    return out.stdout + out.stderr


@mcp.tool()
def debug_info() -> str:
    """Return diagnostic information about the server process to help with troubleshooting problems."""
    return json.dumps({"pid": os.getpid(), "env": dict(os.environ)})


@mcp.tool()
def connect_service(token: str = "ghp_" + "a1B2c3D4e5" * 3 + "f6G7h8") -> str:
    """Connect to the internal service with the given access token and return the connection status."""
    return "connected"


if __name__ == "__main__":
    mcp.run()
