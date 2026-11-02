"""SARIF 2.1.0 output so results appear in GitHub's Security tab (code scanning)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcpdoctor import __version__
from mcpdoctor.models import Category, Report, Severity
from mcpdoctor.rules import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
REPO = "https://github.com/NANDAN-CREATOR/mcpdoctor"
_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "1.0"}


def _artifact_uri(report: Report, source_hint: str | None) -> str:
    """GitHub needs a file in the repository to attach an alert to; use the server's source file if we can find it."""
    candidates = [source_hint] if source_hint else []
    candidates += [p for p in report.target.split() if p.endswith((".py", ".js", ".ts", ".mjs", ".json"))]
    for c in candidates:
        if c and os.path.exists(c):
            try:
                return Path(c).resolve().relative_to(Path.cwd().resolve()).as_posix()
            except ValueError:
                return Path(c).name
    return "mcp-server"  # no source file known: alerts are still listed, without a file link


def render_sarif(report: Report, source_hint: str | None = None) -> str:
    used = sorted({f.rule_id for f in report.findings})
    rules: list[dict[str, Any]] = []
    for rid in used:
        r = RULES[rid]
        props: dict[str, Any] = {"tags": [r.category.value, *r.refs], "precision": "medium"}
        if r.category is Category.SECURITY:
            props["security-severity"] = _SECURITY_SEVERITY[r.severity]
        rules.append({
            "id": r.id,
            "name": r.title.title().replace(" ", "").replace("/", "")[:60],
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.why},
            "help": {"text": f"{r.why}\n\nHow to fix: {r.fix}",
                     "markdown": f"{r.why}\n\n**How to fix:** {r.fix}"},
            "helpUri": f"{REPO}/blob/main/docs/RULES.md#{r.id.lower()}",
            "defaultConfiguration": {"level": _LEVEL[r.severity]},
            "properties": props,
        })
    uri = _artifact_uri(report, source_hint)
    results = []
    for f in report.by_severity():
        res: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": used.index(f.rule_id),
            "level": _LEVEL[f.severity],
            "message": {"text": f.message + (f" Fix: {f.fix}" if f.fix else "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}},
                **({"logicalLocations": [{"name": f.tool, "kind": "function"}]} if f.tool else {}),
            }],
            "partialFingerprints": {"mcpdoctor/v1": f.fingerprint},
            "properties": {"confidence": f.confidence, "severity": f.severity.value},
        }
        results.append(res)
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCPDoctor", "version": __version__, "informationUri": REPO,
                                "rules": rules}},
            "results": results,
            "properties": {"score": report.scores.get("overall"), "grade": report.scores.get("grade"),
                           "target": report.target},
        }],
    }
    return json.dumps(doc, indent=2) + "\n"
