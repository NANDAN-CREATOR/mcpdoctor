from __future__ import annotations

from html import escape

from mcpdoctor.models import Report
from mcpdoctor.scoring import badge_color


def _width(text: str) -> int:
    # Verdana 11px averages ~6.6px per character; good enough for a flat badge.
    return int(len(text) * 6.6) + 12


def badge_svg(label: str, message: str, color: str) -> str:
    lw, mw = _width(label), _width(message)
    total = lw + mw
    label_e, message_e = escape(label), escape(message)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" '
        f'aria-label="{label_e}: {message_e}">'
        f'<title>{label_e}: {message_e}</title>'
        '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.0f}" y="14">{label_e}</text>'
        f'<text x="{lw + mw / 2:.0f}" y="14">{message_e}</text></g></svg>\n'
    )


def score_badge(report: Report) -> str:
    s = report.scores
    return badge_svg("MCP health", f"{s.get('overall', 0)} {s.get('grade', '?')}", badge_color(s.get("grade", "?")))
