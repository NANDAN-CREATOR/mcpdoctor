"""Core data models shared by every MCPDoctor component."""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Category(str, enum.Enum):
    PROTOCOL = "protocol"
    QUALITY = "quality"
    SECURITY = "security"
    BEHAVIOR = "behavior"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    tool: str | None = None
    evidence: str | None = None
    fix: str = ""
    confidence: str = "high"  # high | medium | low

    @property
    def fingerprint(self) -> str:
        """Stable id used for baselines and SARIF de-duplication."""
        raw = f"{self.rule_id}|{self.tool or ''}|{self.message[:120]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "tool": self.tool,
            "evidence": self.evidence,
            "fix": self.fix,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    title: str | None = None
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def properties(self) -> dict[str, Any]:
        props = self.input_schema.get("properties")
        return props if isinstance(props, dict) else {}

    @property
    def required(self) -> list[str]:
        req = self.input_schema.get("required")
        return list(req) if isinstance(req, list) else []

    @property
    def read_only(self) -> bool | None:
        v = self.annotations.get("read_only_hint")
        return v if isinstance(v, bool) else None

    @property
    def destructive(self) -> bool | None:
        v = self.annotations.get("destructive_hint")
        return v if isinstance(v, bool) else None

    def fingerprint(self) -> str:
        """Hash of everything an agent can see about this tool (used for rug-pull detection)."""
        blob = json.dumps(
            {
                "name": self.name,
                "title": self.title,
                "description": self.description,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
                "annotations": self.annotations,
            },
            sort_keys=True,
            ensure_ascii=True,
            default=str,
        )
        return hashlib.sha256(blob.encode()).hexdigest()

    def all_text(self) -> list[tuple[str, str]]:
        """Every free-text field an LLM would read, as (location, text) pairs."""
        out: list[tuple[str, str]] = []
        if self.title:
            out.append(("title", self.title))
        out.append(("description", self.description or ""))
        _walk_schema_text(self.input_schema, "inputSchema", out)
        return out

    def token_estimate(self) -> int:
        """Rough token cost of exposing this tool to a model (about 4 characters per token)."""
        blob = json.dumps(
            {"name": self.name, "description": self.description, "schema": self.input_schema},
            default=str,
        )
        return max(1, len(blob) // 4)


def _walk_schema_text(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}"
            if key in ("description", "title") and isinstance(value, str) or key == "default" and isinstance(value, str):
                out.append((child, value))
            elif key in ("enum", "examples") and isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        out.append((f"{child}[{i}]", item))
            else:
                _walk_schema_text(value, child, out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_schema_text(item, f"{path}[{i}]", out)


@dataclass
class CallRecord:
    """The outcome of one tools/call made by MCPDoctor."""

    tool: str
    args: dict[str, Any]
    completed: bool  # the server answered (even with an error)
    is_error: bool = False
    text: str = ""
    structured: Any = None
    latency_ms: float = 0.0
    exception: str | None = None  # transport-level failure description
    timed_out: bool = False
    size_bytes: int = 0

    @property
    def succeeded(self) -> bool:
        return self.completed and not self.is_error


@dataclass
class Coverage:
    """What was and was not tested - reported so a clean result is never over-trusted."""

    name: str
    status: str  # ran | skipped | not_applicable
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class ServerIdentity:
    name: str = "unknown"
    version: str = ""
    protocol_version: str = ""
    instructions: str | None = None


@dataclass
class Report:
    target: str
    version: str
    started_at: str
    duration_s: float = 0.0
    server: ServerIdentity = field(default_factory=ServerIdentity)
    tools: list[ToolInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    evaluation: dict[str, Any] = field(default_factory=dict)
    scores: dict[str, Any] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    def by_severity(self, minimum: Severity = Severity.INFO) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.severity.rank >= minimum.rank),
            key=lambda f: (-f.severity.rank, f.rule_id, f.tool or ""),
        )

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "mcpdoctor.report/1",
            "tool_version": self.version,
            "target": self.target,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 2),
            "server": {
                "name": self.server.name,
                "version": self.server.version,
                "protocol_version": self.server.protocol_version,
            },
            "tools": [
                {
                    "name": t.name,
                    "fingerprint": t.fingerprint(),
                    "token_estimate": t.token_estimate(),
                    "read_only_hint": t.read_only,
                }
                for t in self.tools
            ],
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.by_severity()],
            "coverage": [c.to_dict() for c in self.coverage],
            "evaluation": self.evaluation,
            "scores": self.scores,
            "options": self.options,
        }
