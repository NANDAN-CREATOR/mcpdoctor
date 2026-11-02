"""Small text helpers shared by the detectors."""

from __future__ import annotations

import re

_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

STOPWORDS = frozenset(
    ["a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with", "from", "by", "is", "are", "be", "this", "that", "it", "its", "as", "at", "into", "can", "will", "returns", "return", "get", "gets", "using", "use", "used", "given", "tool", "function"]
)


def name_tokens(name: str) -> list[str]:
    """Split snake_case / kebab-case / camelCase identifiers into lower-case words."""
    spaced = _CAMEL.sub("_", name)
    return [t.lower() for t in _WORD_SPLIT.split(spaced) if t]


def content_words(text: str) -> set[str]:
    return {w for w in (t.lower() for t in _WORD_SPLIT.split(text)) if len(w) > 2 and w not in STOPWORDS}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    out = text[s:e].replace("\n", " ").strip()
    return ("..." if s > 0 else "") + out + ("..." if e < len(text) else "")


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]")


def clean(text: str) -> str:
    """Strip terminal escape sequences and invisible/bidi control characters from untrusted text before display."""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?", "", text)
    return _CONTROL.sub("", text)


def redact(secret: str) -> str:
    return secret[:4] + "..." + f"({len(secret)} chars)"
