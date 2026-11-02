"""Report renderers: terminal, JSON, SARIF, Markdown, HTML and SVG badge."""

from mcpdoctor.report.badge import badge_svg, score_badge
from mcpdoctor.report.html import render_html
from mcpdoctor.report.jsonout import render_json
from mcpdoctor.report.markdown import render_markdown
from mcpdoctor.report.sarif import render_sarif
from mcpdoctor.report.terminal import render_terminal

__all__ = ["badge_svg", "score_badge", "render_html", "render_json", "render_markdown", "render_sarif",
           "render_terminal"]
