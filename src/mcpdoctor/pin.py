"""Tool pinning: detect "rug pulls" where a tool's description changes after you approved it."""

from __future__ import annotations

import difflib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcpdoctor.models import Finding, ServerIdentity, Severity, ToolInfo
from mcpdoctor.rules import make_finding

LOCK_SCHEMA = "mcpdoctor.lock/1"
DEFAULT_LOCKFILE = "mcpdoctor.lock.json"


def build_lock(tools: list[ToolInfo], identity: ServerIdentity, target: str) -> dict[str, Any]:
    return {
        "schema": LOCK_SCHEMA,
        "target": target,
        "server": {"name": identity.name, "version": identity.version},
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": {
            t.name: {
                "fingerprint": t.fingerprint(),
                "description": t.description,
                "parameters": sorted(t.properties),
            }
            for t in sorted(tools, key=lambda x: x.name)
        },
    }


def write_lock(path: str | Path, lock: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def read_lock(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if data.get("schema") != LOCK_SCHEMA:
        raise ValueError(f"{path} is not an {LOCK_SCHEMA} file")
    return data


def compare_lock(lock: dict[str, Any], tools: list[ToolInfo]) -> list[Finding]:
    pinned: dict[str, Any] = lock.get("tools", {})
    current = {t.name: t for t in tools}
    findings: list[Finding] = []
    for name, entry in pinned.items():
        tool = current.get(name)
        if tool is None:
            findings.append(make_finding(
                "S010", f"Pinned tool '{name}' is no longer offered by the server.", tool=name,
                severity=Severity.LOW))
            continue
        if tool.fingerprint() != entry["fingerprint"]:
            diff = "\n".join(difflib.unified_diff(
                str(entry.get("description", "")).splitlines(), tool.description.splitlines(),
                "pinned", "current", lineterm="", n=0))
            what = "description" if diff else "schema or annotations"
            findings.append(make_finding(
                "S010", f"Tool '{name}' {what} changed since it was pinned.", tool=name,
                evidence=diff[:380] or "schema/annotations differ"))
    for name in sorted(set(current) - set(pinned)):
        findings.append(make_finding(
            "S010", f"Tool '{name}' was added after the lock file was created.", tool=name,
            severity=Severity.MEDIUM))
    return findings
