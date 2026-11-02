"""Static security analysis of everything a model reads about a server.

Design goal: *precision*. Published audits of existing pattern-matching scanners found that most flagged
"prompt injection" matches were ordinary dependency hints such as "You MUST call this function first".
So this scanner never flags bare imperative wording. It flags only combinations that have no benign reading:

* overriding earlier instructions or the system prompt,
* concealing something from the user,
* telling the model to read sensitive material *and* to move it somewhere,
* sending data to an external URL,
* hidden / invisible characters and decodable encoded payloads,
* embedded credentials.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections import Counter

from mcpdoctor.models import Finding, ServerIdentity, Severity, ToolInfo
from mcpdoctor.rules import make_finding
from mcpdoctor.textutil import name_tokens, redact, snippet

# --------------------------------------------------------------------------- S001 patterns
_OVERRIDE = [
    re.compile(r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+|every\s+)*"
               r"(previous|prior|above|earlier|other|system|safety)\s+(instructions?|prompts?|rules?|"
               r"messages?|guidelines?|constraints?|policies)\b", re.I),
    re.compile(r"\byou are now\b", re.I),
    re.compile(r"\bnew (system )?instructions?\s*:", re.I),
    re.compile(r"<\s*/?\s*(system|important|instructions?|secret|hidden)\s*>", re.I),
    re.compile(r"\b(reveal|print|output|repeat)\s+(your|the)\s+(system\s+prompt|hidden\s+instructions)\b", re.I),
]
_CONCEAL = [
    re.compile(r"\b(do not|don't|never|without)\s+(tell|telling|inform|informing|mention|mentioning|notify|"
               r"notifying|alert|alerting|reveal|revealing|show|showing|disclose|disclosing)\s+"
               r"(this\s+|that\s+|it\s+)?(to\s+)?(the\s+)?(user|human|person|operator|anyone)\b", re.I),
    re.compile(r"\b(silently|secretly|covertly|stealthily)\b", re.I),
    re.compile(r"\b(hide|conceal)\s+(this|it|that)\b", re.I),
    re.compile(r"\bthe user (must|should|can)\s*(not|never|n't)\s+(see|know|find out|be told)\b", re.I),
]
_SENSITIVE = re.compile(
    r"(~/|\$HOME/|/home/\w+/|/Users/\w+/)?\.(ssh|aws|gnupg|kube|docker)\b|\bid_(rsa|ed25519|ecdsa)\b|"
    r"(^|[\s/'\"])\.env\b|/etc/(passwd|shadow)\b|\bmcp\.json\b|\bclaude_desktop_config\b|\bprivate keys?\b",
    re.I,
)
_MOVE_VERB = re.compile(
    r"\b(read|cat|open|include|send|attach|append|pass|provide|add|upload|post|exfiltrate|copy|collect|"
    r"forward|submit|transmit|leak|email|share|paste|put|embed)\b", re.I)
_DIRECTIVE = re.compile(
    r"\b(you must|you should|you need to|always|make sure|ensure that|first|before (using|calling|running)|"
    r"required|do this|be sure)\b", re.I)
_EXFIL = re.compile(
    r"\b(send|post|upload|forward|transmit|exfiltrate|leak|submit|deliver|report)\b[^.\n]{0,80}?"
    r"\b(to|at|via|through)\b[^.\n]{0,20}?https?://\S+", re.I)

# --------------------------------------------------------------------------- S002
_INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

# --------------------------------------------------------------------------- S003
_B64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX = re.compile(r"\b[0-9a-fA-F]{48,}\b")

# --------------------------------------------------------------------------- S006
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
_GENERIC_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=.!@#$%^&*]{12,})['\"]?")

# --------------------------------------------------------------------------- S005
_EXEC_NAME_TOKENS = frozenset(["shell", "bash", "exec", "execute", "eval", "command", "cmd", "terminal", "subprocess", "spawn", "sh", "powershell"])
_EXEC_DESC = re.compile(
    r"\b(run|runs|execute|executes|evaluate|evaluates)\s+(an\s+|any\s+|arbitrary\s+|the\s+given\s+|a\s+)?"
    r"(arbitrary\s+|shell\s+|bash\s+|system\s+|python\s+|javascript\s+)?(command|code|script|shell|program)s?\b",
    re.I)
_CMD_PARAMS = frozenset(["command", "cmd", "code", "script", "expression", "expr", "shell", "bash", "statement"])
_SQL_PARAMS = frozenset(["sql", "query", "statement"])


def scan_metadata(tools: list[ToolInfo], identity: ServerIdentity | None = None) -> list[Finding]:
    findings: list[Finding] = []
    blobs: list[tuple[str | None, str, str]] = []  # (tool, location, text)
    for tool in tools:
        for loc, text in tool.all_text():
            blobs.append((tool.name, loc, text))
        blobs.append((tool.name, "name", tool.name))
    if identity and identity.instructions:
        blobs.append((None, "server.instructions", identity.instructions))

    for tool_name, loc, text in blobs:
        if not text:
            continue
        findings.extend(_scan_text(tool_name, loc, text))

    findings.extend(_shadowing(tools))
    findings.extend(_exec_surface(tools))
    return _dedupe(findings)


def _scan_text(tool: str | None, loc: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    where = f"'{tool}' ({loc})" if tool else loc

    # S002 invisible characters
    hidden = _INVISIBLE.findall(text)
    if hidden:
        counts = Counter(f"U+{ord(c):04X} {unicodedata.name(c, 'UNKNOWN')}" for c in hidden)
        detail = ", ".join(f"{k} x{v}" for k, v in counts.most_common(4))
        decoded = _decode_tag_chars(text)
        extra = f" Hidden ASCII decoded from tag characters: {decoded!r}." if decoded else ""
        out.append(make_finding("S002", f"{where} contains {len(hidden)} invisible control character(s): "
                                f"{detail}.{extra}", tool=tool, evidence=detail))

    visible = _INVISIBLE.sub("", text)

    # S001 hijacking
    reasons: list[str] = []
    evidence = ""
    strong = False
    for rx in _OVERRIDE:
        m = rx.search(visible)
        if m:
            reasons.append("tries to override earlier instructions")
            evidence = evidence or snippet(visible, m.start(), m.end())
            strong = True
            break
    for rx in _CONCEAL:
        m = rx.search(visible)
        if m:
            reasons.append("asks the model to conceal something from the user")
            evidence = evidence or snippet(visible, m.start(), m.end())
            strong = True
            break
    m = _EXFIL.search(visible)
    if m:
        reasons.append("tells the model to send data to an external URL")
        evidence = evidence or snippet(visible, m.start(), m.end())
        strong = True
    for m in _SENSITIVE.finditer(visible):
        window = visible[max(0, m.start() - 70): m.end() + 70]
        if _MOVE_VERB.search(window) and _DIRECTIVE.search(visible):
            reasons.append("directs the model to access sensitive material")
            evidence = evidence or snippet(visible, m.start(), m.end())
            break
    if reasons:
        sev = Severity.HIGH if strong else Severity.MEDIUM
        out.append(make_finding(
            "S001", f"{where} {'; '.join(dict.fromkeys(reasons))}.", tool=tool, evidence=evidence,
            severity=sev, confidence="high" if strong else "medium"))

    # S003 encoded payloads
    for m in _B64.finditer(visible):
        b64_text = _try_b64(m.group(0))
        if b64_text:
            out.append(make_finding(
                "S003", f"{where} contains a base64 blob that decodes to readable text: {b64_text[:80]!r}.",
                tool=tool, evidence=m.group(0)[:80]))
            break
    for m in _HEX.finditer(visible):
        hex_text = _try_hex(m.group(0))
        if hex_text:
            out.append(make_finding(
                "S003", f"{where} contains a hex blob that decodes to readable text: {hex_text[:80]!r}.",
                tool=tool, evidence=m.group(0)[:80]))
            break

    # S006 secrets
    for label, rx in _SECRET_PATTERNS:
        m = rx.search(visible)
        if m:
            out.append(make_finding(
                "S006", f"{where} contains what looks like a {label}: {redact(m.group(0))}.", tool=tool,
                evidence=redact(m.group(0))))
    for m in _GENERIC_SECRET.finditer(visible):
        value = m.group(2)
        if any(c.isdigit() for c in value) and any(c.isalpha() for c in value) and not value.lower().startswith(
                ("your", "example", "xxxx", "<")):
            out.append(make_finding(
                "S006", f"{where} contains a hard-coded {m.group(1).lower()} value: {redact(value)}.",
                tool=tool, evidence=redact(value), severity=Severity.HIGH, confidence="medium"))
            break
    return out


def _decode_tag_chars(text: str) -> str:
    chars = [chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E]
    return "".join(chars)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) >= 24 and _printable_ratio(raw) > 0.9 and b" " in raw:
        return raw.decode("ascii", "replace")
    return None


def _try_hex(blob: str) -> str | None:
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return None
    if len(raw) >= 24 and _printable_ratio(raw) > 0.9 and b" " in raw:
        return raw.decode("ascii", "replace")
    return None


def _shadowing(tools: list[ToolInfo]) -> list[Finding]:
    out: list[Finding] = []
    names = [t.name for t in tools if len(t.name) >= 4]
    for tool in tools:
        text = _INVISIBLE.sub("", tool.description or "")
        for other in names:
            if other == tool.name:
                continue
            q = r"[`'\"]?"
            pat = re.compile(
                rf"\b(when|whenever)\s+(you\s+)?(use|using|call|calling|invoke|invoking)\s+{q}{re.escape(other)}{q}"
                r"[^.\n]{0,120}?\b(always|must|should|also|ensure|make sure|instead|replace|change|set|add|"
                r"include|bcc|cc|append)\b", re.I)
            m = pat.search(text) or re.search(
                rf"\b(override|replace|shadow|intercept|hijack)\w*\s+(the\s+)?{q}{re.escape(other)}{q}", text, re.I)
            if m:
                out.append(make_finding(
                    "S004", f"Tool '{tool.name}' description steers the behaviour of other tool '{other}'.",
                    tool=tool.name, evidence=snippet(text, m.start(), m.end()), confidence="medium"))
    return out


def _exec_surface(tools: list[ToolInfo]) -> list[Finding]:
    out: list[Finding] = []
    for tool in tools:
        toks = set(name_tokens(tool.name))
        pnames = {p.lower(): p for p in tool.properties}
        cmd_param = next((pnames[p] for p in pnames if p in _CMD_PARAMS), None)
        sql_param = next((pnames[p] for p in pnames if p in _SQL_PARAMS), None)
        name_hit = bool(toks & _EXEC_NAME_TOKENS)
        desc_hit = bool(_EXEC_DESC.search(tool.description or ""))
        if cmd_param and (name_hit or desc_hit or toks & {"run", "eval"}):
            out.append(make_finding(
                "S005", f"Tool '{tool.name}' executes caller-supplied commands/code via parameter '{cmd_param}'.",
                tool=tool.name, evidence=(tool.description or "")[:200]))
        elif sql_param and (name_hit or toks & {"sql", "query", "run"} or "sql" in (tool.description or "").lower()):
            sev = Severity.LOW if tool.read_only is True else Severity.MEDIUM
            out.append(make_finding(
                "S005", f"Tool '{tool.name}' accepts raw SQL via parameter '{sql_param}'"
                f"{' (annotated read-only: verify it is enforced)' if tool.read_only else ''}.",
                tool=tool.name, severity=sev, confidence="medium"))
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        key = f"{f.rule_id}|{f.tool}|{f.message}"
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
