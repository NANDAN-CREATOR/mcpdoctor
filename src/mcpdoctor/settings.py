"""Project settings from ``.mcpdoctor.yml`` (optional)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcpdoctor.lint import LintConfig
from mcpdoctor.rules import RULES

CANDIDATES = (".mcpdoctor.yml", ".mcpdoctor.yaml")


class SettingsError(ValueError):
    pass


@dataclass
class Settings:
    fail_on: str | None = None
    min_score: int | None = None
    ignore_rules: set[str] = field(default_factory=set)
    ignore_pairs: set[tuple[str, str]] = field(default_factory=set)
    lint: LintConfig = field(default_factory=LintConfig)
    slow_ms: float | None = None
    max_calls: int | None = None
    source: str | None = None


def load_settings(path: str | Path | None = None) -> Settings:
    p: Path | None = Path(path) if path else next((Path(c) for c in CANDIDATES if Path(c).exists()), None)
    if p is None:
        return Settings()
    try:
        data: Any = yaml.safe_load(p.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SettingsError(f"cannot read settings file {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise SettingsError(f"{p}: top level must be a mapping")
    s = Settings(source=str(p))
    s.fail_on = data.get("fail_on")
    s.min_score = data.get("min_score")
    s.slow_ms = data.get("slow_ms")
    s.max_calls = data.get("max_calls")
    for item in data.get("ignore", []) or []:
        if isinstance(item, str):
            _check_rule(item, p)
            s.ignore_rules.add(item)
        elif isinstance(item, dict) and "rule" in item:
            _check_rule(str(item["rule"]), p)
            if item.get("tool"):
                s.ignore_pairs.add((str(item["rule"]), str(item["tool"])))
            else:
                s.ignore_rules.add(str(item["rule"]))
        else:
            raise SettingsError(f"{p}: each 'ignore' entry must be a rule id or {{rule:, tool:}}")
    lint = data.get("lint") or {}
    for key, value in lint.items():
        if not hasattr(s.lint, key):
            raise SettingsError(f"{p}: unknown lint setting {key!r}")
        setattr(s.lint, key, value)
    return s


def _check_rule(rule_id: str, path: Path) -> None:
    if rule_id not in RULES:
        raise SettingsError(f"{path}: unknown rule id {rule_id!r} (see: mcpdoctor rules)")
