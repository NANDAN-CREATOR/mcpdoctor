"""Build *schema-valid* example arguments from a tool's JSON Schema.

Used by the contract test (does the tool accept what its own schema promises?) and as the benign baseline
that every security probe mutates one parameter of.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from mcpdoctor.models import ToolInfo
from mcpdoctor.textutil import name_tokens

_PATTERN_CANDIDATES = [
    "allowed.txt", "test", "1", "abc", "a1", "item", "2024-01-15", "user@example.com",
    "https://example.com/", "test.txt", "A1", "TEST", "my_item", "x",
]
_QUERY_TOKENS = frozenset(["query", "search", "term", "keyword", "q", "text", "filter", "name", "title"])
_COUNT_TOKENS = frozenset(["limit", "count", "n", "size", "top", "num", "results", "rows", "take", "per_page", "max", "length"])


def _resolve(schema: dict[str, Any], root: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/") and depth < 8:
        node: Any = root
        for part in ref[2:].split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        if isinstance(node, dict):
            merged = {**node, **{k: v for k, v in schema.items() if k != "$ref"}}
            return _resolve(merged, root, depth + 1)
    return schema


def sample_value(schema: Any, name: str = "", root: dict[str, Any] | None = None, depth: int = 0) -> Any:
    if not isinstance(schema, dict) or depth > 6:
        return "test"
    root = root or schema
    schema = _resolve(schema, root)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    if "default" in schema and schema["default"] is not None:
        return schema["default"]
    ex = schema.get("examples")
    if isinstance(ex, list) and ex:
        return ex[0]
    for key in ("anyOf", "oneOf"):
        opts = schema.get(key)
        if isinstance(opts, list) and opts:
            for opt in opts:
                if isinstance(opt, dict) and opt.get("type") != "null":
                    return sample_value(opt, name, root, depth + 1)
    if isinstance(schema.get("allOf"), list) and schema["allOf"]:
        merged: dict[str, Any] = {}
        for part in schema["allOf"]:
            if isinstance(part, dict):
                merged.update(_resolve(part, root))
        return sample_value(merged, name, root, depth + 1)

    typ = schema.get("type")
    if isinstance(typ, list):
        typ = next((t for t in typ if t != "null"), "null")
    toks = set(name_tokens(name))

    if typ == "string" or (typ is None and "properties" not in schema and "items" not in schema):
        return _sample_string(schema, toks)
    if typ == "integer":
        lo = schema.get("minimum", schema.get("exclusiveMinimum"))
        hi = schema.get("maximum")
        val = 3 if toks & _COUNT_TOKENS else 1
        if isinstance(lo, int | float) and val < lo:
            val = int(lo) + (1 if "exclusiveMinimum" in schema and "minimum" not in schema else 0)
        if isinstance(hi, int | float) and val > hi:
            val = int(hi)
        return val
    if typ == "number":
        lo = schema.get("minimum")
        return float(lo) if isinstance(lo, int | float) and lo > 1 else 1.0
    if typ == "boolean":
        return False
    if typ == "null":
        return None
    if typ == "array":
        items = schema.get("items", {})
        n = max(1, int(schema.get("minItems", 1) or 1))
        return [sample_value(items, name, root, depth + 1) for _ in range(min(n, 3))]
    if typ == "object" or "properties" in schema:
        props = schema.get("properties", {}) or {}
        req = schema.get("required", []) or []
        return {k: sample_value(props.get(k, {}), k, root, depth + 1) for k in req}
    return "test"


def _sample_string(schema: dict[str, Any], toks: set[str]) -> str:
    fmt = schema.get("format")
    pattern = schema.get("pattern")
    value: str
    if fmt in ("uri", "url", "iri"):
        value = "https://example.com/"
    elif fmt == "email":
        value = "user@example.com"
    elif fmt == "date":
        value = "2024-01-15"
    elif fmt == "date-time":
        value = "2024-01-15T10:00:00Z"
    elif fmt == "uuid":
        value = str(uuid.UUID(int=1))
    elif fmt in ("hostname", "idn-hostname"):
        value = "example.com"
    elif fmt in ("ipv4",):
        value = "93.184.216.34"
    elif toks & {"path", "file", "filename", "filepath"}:
        value = "allowed.txt"
    elif toks & {"url", "uri", "link", "href", "endpoint"}:
        value = "https://example.com/"
    elif "email" in toks:
        value = "user@example.com"
    elif toks & {"date", "day"}:
        value = "2024-01-15"
    elif toks & {"host", "hostname", "domain"}:
        value = "example.com"
    elif toks & _QUERY_TOKENS:
        value = "test"
    elif "id" in toks:
        value = "1"
    else:
        value = "test"
    if isinstance(pattern, str):
        for cand in [value, *_PATTERN_CANDIDATES]:
            try:
                if re.search(pattern, cand):
                    value = cand
                    break
            except re.error:
                break
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and len(value) < min_len:
        value = value + "x" * (min_len - len(value))
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and len(value) > max_len:
        value = value[:max_len]
    return value


def minimal_args(tool: ToolInfo) -> dict[str, Any]:
    """Arguments containing only the required parameters."""
    props = tool.properties
    return {name: sample_value(props.get(name, {}), name, tool.input_schema) for name in tool.required}


def full_args(tool: ToolInfo) -> dict[str, Any]:
    """Arguments containing every declared parameter."""
    return {name: sample_value(s, name, tool.input_schema) for name, s in tool.properties.items()}


def string_params(tool: ToolInfo) -> list[str]:
    out = []
    for name, s in tool.properties.items():
        if not isinstance(s, dict):
            continue
        s2 = _resolve(s, tool.input_schema)
        typ = s2.get("type")
        if typ == "string" or (isinstance(typ, list) and "string" in typ) or (
            typ is None and any(isinstance(o, dict) and o.get("type") == "string"
                                for o in (s2.get("anyOf") or s2.get("oneOf") or []))
        ):
            out.append(name)
    return out


def param_type(tool: ToolInfo, name: str) -> str | None:
    s = tool.properties.get(name)
    if not isinstance(s, dict):
        return None
    s = _resolve(s, tool.input_schema)
    typ = s.get("type")
    if isinstance(typ, list):
        typ = next((t for t in typ if t != "null"), None)
    if typ is None:
        for key in ("anyOf", "oneOf"):
            for o in s.get(key) or []:
                if isinstance(o, dict) and o.get("type") not in (None, "null"):
                    return o["type"]
    return typ
