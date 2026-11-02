"""Turn findings into scores, a letter grade and a pass/fail verdict.

The model is intentionally simple so that anyone can predict how a fix changes the score:

* Each finding costs points by severity: critical 40, high 20, medium 8, low 3, info 0.
* Points are scaled by confidence (high 100 %, medium 60 %, low 30 %).
* Repeats of the same rule within a category have diminishing cost (100 %, 50 %, 25 %, 25 % ...), so
  thirty undocumented tools do not hide a single injection bug, nor the other way round.
* Category score = 100 - total cost (never below 0).
* Overall = weighted average (security 50 %, quality 25 %, reliability 25 %); categories that were not
  assessed (for example reliability in a static-only run) are left out and the weights renormalised.
* Hard caps: any critical finding caps the overall score at 49 (grade F); any high *security* finding caps
  it at 74 (grade C); any other high finding caps it at 84 (grade B).
"""

from __future__ import annotations

from typing import Any

from mcpdoctor.models import Category, Finding, Severity

COST = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 0}
CONFIDENCE = {"high": 1.0, "medium": 0.6, "low": 0.3}
REPEAT = [1.0, 0.5, 0.25]
WEIGHTS = {"security": 0.50, "quality": 0.25, "reliability": 0.25}


def _group(cat: Category) -> str:
    return {Category.SECURITY: "security", Category.QUALITY: "quality"}.get(cat, "reliability")


def grade(score: float) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return letter
    return "F"


def compute(findings: list[Finding], assessed: set[str]) -> dict[str, Any]:
    """``assessed`` is the subset of {'security','quality','reliability'} that was actually tested."""
    cost: dict[str, float] = {k: 0.0 for k in WEIGHTS}
    seen: dict[tuple[str, str], int] = {}
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        grp = _group(f.category)
        n = seen.get((grp, f.rule_id), 0)
        seen[(grp, f.rule_id)] = n + 1
        cost[grp] += COST[f.severity] * CONFIDENCE.get(f.confidence, 1.0) * REPEAT[min(n, len(REPEAT) - 1)]

    cats: dict[str, Any] = {}
    for grp in WEIGHTS:
        if grp in assessed:
            s = max(0.0, 100.0 - cost[grp])
            cats[grp] = {"score": round(s), "grade": grade(s), "assessed": True}
        else:
            cats[grp] = {"score": None, "grade": "n/a", "assessed": False}

    live = {g: WEIGHTS[g] for g in WEIGHTS if cats[g]["assessed"]}
    total_w = sum(live.values()) or 1.0
    overall = sum(cats[g]["score"] * w for g, w in live.items()) / total_w if live else 0.0

    caps: list[str] = []
    if any(f.severity is Severity.CRITICAL for f in findings):
        if overall > 49:
            caps.append("critical finding present: overall capped at 49")
        overall = min(overall, 49)
    if any(f.severity is Severity.HIGH and f.category is Category.SECURITY for f in findings):
        if overall > 74:
            caps.append("high-severity security finding present: overall capped at 74")
        overall = min(overall, 74)
    if any(f.severity is Severity.HIGH for f in findings):
        if overall > 84:
            caps.append("high-severity finding present: overall capped at 84")
        overall = min(overall, 84)

    overall_i = round(overall)
    return {
        "overall": overall_i,
        "grade": grade(overall_i),
        "categories": cats,
        "caps": caps,
        "model": "mcpdoctor.score/1",
    }


def badge_color(letter: str) -> str:
    return {"A": "#2ea44f", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44"}.get(letter, "#9f9f9f")
