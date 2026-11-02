"""Regenerate docs/RULES.md from the rule catalog (CI fails if the committed file is stale)."""
from pathlib import Path

from mcpdoctor.cli import rules_markdown

Path(__file__).resolve().parent.parent.joinpath("docs", "RULES.md").write_text(rules_markdown())
