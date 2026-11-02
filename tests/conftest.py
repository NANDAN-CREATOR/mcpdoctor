from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpdoctor.models import Report
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.target import Target

SERVERS = Path(__file__).resolve().parent.parent / "examples" / "servers"
_CACHE: dict[tuple[str, str], Report] = {}


def scan_server(name: str, **opts: object) -> Report:
    """Scan one of the demo servers (cached for the test session)."""
    key = (name, repr(sorted(opts.items())))
    if key not in _CACHE:
        options = ScanOptions(time_budget_s=120, **opts)  # type: ignore[arg-type]
        _CACHE[key] = asyncio.run(scan(Target.from_command([sys.executable, str(SERVERS / name)]), options))
    return _CACHE[key]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def http_server():
    port = free_port()
    proc = subprocess.Popen([sys.executable, str(SERVERS / "good_http.py"), str(port)], cwd=SERVERS,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.skip("could not start the HTTP demo server")
    yield f"http://127.0.0.1:{port}/mcp"
    proc.terminate()
    proc.wait(timeout=10)
