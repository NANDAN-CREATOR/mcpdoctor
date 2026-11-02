"""Static quality lint over tool definitions (no tool is executed)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcpdoctor.models import Finding, ToolInfo
from mcpdoctor.rules import make_finding
from mcpdoctor.textutil import content_words, jaccard, name_tokens


@dataclass
class LintConfig:
    min_description_chars: int = 20
    min_description_words: int = 5
    max_description_chars: int = 1500
    max_tools: int = 40
    max_total_tokens: int = 8000
    overlap_threshold: float = 0.55


_GUIDANCE = re.compile(
    r"\b(use (this )?(tool )?(when|to|for|if|only)|when to use|do not use|don't use|not for|"
    r"instead of|only (for|when|use)|prefer|unlike|rather than|before calling|after calling|"
    r"call this (first|after|before)|requires|must be|should be)\b",
    re.IGNORECASE,
)
_VAGUE_NAMES = frozenset(
    ["run", "do", "doit", "execute", "exec", "process", "handle", "call", "action", "tool", "helper", "util", "utils", "main", "go", "get", "set", "func", "function", "misc", "stuff", "thing", "test", "foo", "bar", "baz"]
)
_VAGUE_PATTERN = re.compile(r"^(tool|func|fn|test|tmp|temp|foo|bar|baz|t|f)[_-]?\d*$", re.IGNORECASE)
_DESTRUCTIVE_VERBS = frozenset(
    ["delete", "remove", "drop", "write", "create", "update", "insert", "send", "post", "execute", "exec", "kill", "truncate", "overwrite", "modify", "edit", "push", "commit", "merge", "upload", "erase", "wipe", "destroy", "rename", "move"]
)
_PATHLIKE = frozenset(["path", "file", "filename", "filepath", "directory", "dir", "folder"])
_URLLIKE = frozenset(["url", "uri", "link", "href", "endpoint"])
_OTHER_FORMAT = frozenset(["email", "date", "datetime", "timestamp", "host", "hostname"])
_CONSTRAINTS = ("pattern", "format", "enum", "const")
_TYPED_KEYS = ("type", "enum", "const", "anyOf", "oneOf", "allOf", "$ref")


def lint_tools(tools: list[ToolInfo], config: LintConfig | None = None) -> list[Finding]:
    cfg = config or LintConfig()
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(_lint_tool(tool, cfg, multi_tool=len(tools) > 1))
    findings.extend(_lint_set(tools, cfg))
    return findings


def _lint_tool(tool: ToolInfo, cfg: LintConfig, multi_tool: bool) -> list[Finding]:
    out: list[Finding] = []
    desc = (tool.description or "").strip()
    n = tool.name

    # Q001 / Q002 / Q003
    if not desc:
        out.append(make_finding("Q001", f"Tool '{n}' has no description.", tool=n))
    else:
        words = len(desc.split())
        if len(desc) < cfg.min_description_chars or words < cfg.min_description_words:
            out.append(make_finding(
                "Q002", f"Tool '{n}' has a {words}-word description: \"{desc}\".", tool=n, evidence=desc))
        if len(desc) > cfg.max_description_chars:
            out.append(make_finding(
                "Q003", f"Tool '{n}' description is {len(desc)} characters (limit {cfg.max_description_chars}).",
                tool=n))

    # Q005 / Q006 / Q007
    undocumented: list[str] = []
    untyped: list[str] = []
    loose: list[str] = []
    for pname, pschema in tool.properties.items():
        if not isinstance(pschema, dict):
            continue
        if not str(pschema.get("description", "")).strip():
            undocumented.append(pname)
        if not any(k in pschema for k in _TYPED_KEYS):
            untyped.append(pname)
        if pschema.get("type") == "string" and not any(k in pschema for k in _CONSTRAINTS):
            toks = set(name_tokens(pname))
            if toks & (_PATHLIKE | _URLLIKE | _OTHER_FORMAT):
                loose.append(pname)
    if undocumented:
        out.append(make_finding(
            "Q005", f"Tool '{n}': parameter(s) without a description: {', '.join(undocumented)}.", tool=n))
    if untyped:
        out.append(make_finding("Q006", f"Tool '{n}': parameter(s) without a type: {', '.join(untyped)}.", tool=n))
    if loose:
        out.append(make_finding(
            "Q007",
            f"Tool '{n}': unconstrained string parameter(s) that look like paths, URLs, dates or emails: "
            f"{', '.join(loose)}.", tool=n))

    # Q009
    name_toks = name_tokens(n)
    if n.lower() in _VAGUE_NAMES or _VAGUE_PATTERN.match(n) or len(n) <= 2 or (
        len(name_toks) == 1 and name_toks[0] in _VAGUE_NAMES
    ):
        out.append(make_finding("Q009", f"Tool name '{n}' does not describe what the tool does.", tool=n))

    # Q012
    if tool.read_only is True:
        verbs = [t for t in name_toks if t in _DESTRUCTIVE_VERBS]
        first = desc.split()[0].lower().strip(".,:;") if desc else ""
        if first in _DESTRUCTIVE_VERBS:
            verbs.append(first)
        if verbs:
            out.append(make_finding(
                "Q012",
                f"Tool '{n}' is annotated read_only_hint=true but its name/description suggests it can modify "
                f"data ('{verbs[0]}').", tool=n))
        if tool.destructive is True:
            out.append(make_finding(
                "Q012", f"Tool '{n}' is annotated both read_only_hint=true and destructive_hint=true.", tool=n))
    _ = multi_tool
    return out


def _lint_set(tools: list[ToolInfo], cfg: LintConfig) -> list[Finding]:
    out: list[Finding] = []
    if not tools:
        return out

    # Q004 (aggregated; only meaningful with more than one tool)
    if len(tools) > 1:
        silent = [t.name for t in tools if t.description.strip() and not _GUIDANCE.search(t.description)]
        if silent:
            shown = ", ".join(silent[:8]) + (" ..." if len(silent) > 8 else "")
            out.append(make_finding(
                "Q004", f"{len(silent)} of {len(tools)} tools give no 'use when / do not use' guidance: {shown}."))

    # Q008 overlap
    words = {t.name: content_words(f"{' '.join(name_tokens(t.name))} {t.description}") for t in tools}
    seen: set[tuple[str, str]] = set()
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            if len(words[a.name]) < 4 or len(words[b.name]) < 4:
                continue
            sim = jaccard(words[a.name], words[b.name])
            same_params = set(a.properties) == set(b.properties) and bool(a.properties)
            if sim >= cfg.overlap_threshold or (sim >= 0.4 and same_params):
                key = tuple(sorted((a.name, b.name)))
                if key not in seen:
                    seen.add(key)  # type: ignore[arg-type]
                    out.append(make_finding(
                        "Q008", f"Tools '{a.name}' and '{b.name}' have {sim:.0%} overlapping descriptions"
                        f"{' and identical parameters' if same_params else ''}.", tool=a.name))

    # Q010 naming convention
    styles: dict[str, list[str]] = {}
    for t in tools:
        style = _name_style(t.name)
        if style:
            styles.setdefault(style, []).append(t.name)
    if len(styles) > 1:
        parts = "; ".join(f"{k}: {', '.join(v[:3])}" for k, v in styles.items())
        out.append(make_finding("Q010", f"Tool names mix naming styles ({parts})."))

    # Q011 annotations
    bare = [t.name for t in tools if t.read_only is None and t.destructive is None]
    if bare:
        shown = ", ".join(bare[:8]) + (" ..." if len(bare) > 8 else "")
        out.append(make_finding(
            "Q011", f"{len(bare)} of {len(tools)} tools have no read_only_hint/destructive_hint: {shown}."))

    # Q013 / Q014
    if len(tools) > cfg.max_tools:
        out.append(make_finding("Q013", f"Server exposes {len(tools)} tools (recommended maximum {cfg.max_tools})."))
    total = sum(t.token_estimate() for t in tools)
    if total > cfg.max_total_tokens:
        biggest = sorted(tools, key=lambda t: -t.token_estimate())[:3]
        out.append(make_finding(
            "Q014", f"Tool definitions cost about {total:,} tokens per request; largest: "
            + ", ".join(f"{t.name} ({t.token_estimate():,})" for t in biggest) + "."))

    # Q015
    no_out = [t.name for t in tools if not t.output_schema]
    if no_out:
        shown = ", ".join(no_out[:8]) + (" ..." if len(no_out) > 8 else "")
        out.append(make_finding("Q015", f"{len(no_out)} of {len(tools)} tools declare no output schema: {shown}."))
    return out


def _name_style(name: str) -> str | None:
    if "_" in name and name == name.lower():
        return "snake_case"
    if "-" in name:
        return "kebab-case"
    if name[:1].islower() and any(c.isupper() for c in name):
        return "camelCase"
    if name[:1].isupper():
        return "PascalCase"
    return None  # a single lower-case word fits every convention
