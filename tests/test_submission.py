from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest
import yaml

from mcpdoctor import leaderboard, submission
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.submission import (
    SubmissionError,
    decide,
    merge_index,
    parse_issue_form,
    read_request,
    slug_for,
    utc_midnight,
    validate_server_url,
    write_outputs,
)
from mcpdoctor.target import Target

PUBLIC = lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port))]  # noqa: E731

BODY = """### MCP server address

https://example.com/mcp

### Permission

- [X] I own this server, or I have permission to test it, and I am happy for the result to be public.
"""


def test_issue_form_is_parsed():
    assert parse_issue_form(BODY)["MCP server address"] == "https://example.com/mcp"
    assert read_request(BODY) == ("https://example.com/mcp", True)
    assert read_request(BODY.replace("[X]", "[ ]")) == ("https://example.com/mcp", False)
    assert read_request("") == ("", False)


def test_valid_public_url_is_accepted():
    assert validate_server_url("https://example.com/mcp", PUBLIC) == "https://example.com/mcp"


@pytest.mark.parametrize("bad", [
    "", "http://example.com/mcp", "ftp://example.com/x", "https://user:pw@example.com/mcp",
    "https://127.0.0.1/mcp", "https://[::1]/mcp", "https://169.254.169.254/latest", "https://localhost/mcp",
    "https://intranet.local/mcp", "https://nodot/mcp", "https://example.com:8443/mcp",
    "https://example.com/mcp?token=abc", "https://example.com/mcp#frag", "https://exa mple.com/mcp",
    "https://example.com/" + "a" * 400, "https://exämple.com/mcp", "javascript:alert(1)",
])
def test_unsafe_or_malformed_urls_are_rejected(bad):
    with pytest.raises(SubmissionError):
        validate_server_url(bad, PUBLIC)


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "172.16.0.9", "127.0.0.1", "169.254.169.254", "::1", "fd00::1",
                                "100.64.0.1"])
def test_hostnames_resolving_to_private_addresses_are_rejected(ip):
    resolver = lambda host, port: [(2, 1, 6, "", (ip, port))]  # noqa: E731
    with pytest.raises(SubmissionError):
        validate_server_url("https://sneaky.example.com/mcp", resolver)


def test_any_private_address_among_several_is_rejected():
    mixed = lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("10.0.0.1", port))]  # noqa: E731
    with pytest.raises(SubmissionError):
        validate_server_url("https://rebind.example.com/mcp", mixed)


def test_unresolvable_domain_is_rejected():
    def boom(host, port):
        raise OSError("no such host")
    with pytest.raises(SubmissionError):
        validate_server_url("https://does-not-exist.example.com/mcp", boom)


def test_daily_limit_is_five_and_per_user_limit_is_two():
    assert submission.DAILY_LIMIT == 5 and leaderboard.DAILY_LIMIT == submission.DAILY_LIMIT
    assert submission.PER_USER_LIMIT == leaderboard.PER_USER_LIMIT == 2
    today = [{"user": "a"}, {"user": "b"}, {"user": "c"}, {"user": "d"}]
    assert decide(today, "e", "owner").allowed          # 4 used: the 5th is allowed
    assert not decide(today + [{"user": "e"}], "f", "owner").allowed   # 5 used: full
    assert not decide([{"user": "a"}, {"user": "A"}], "a", "owner").allowed   # 2 per person, case-insensitive
    assert decide([{"user": "a"}], "a", "owner").allowed
    assert decide([{"user": "owner"}] * 3, "owner", "owner").allowed   # owner exempt from the per-person limit
    assert not decide([{"user": "x"}] * 5, "owner", "owner").allowed   # but not from the daily total


def test_midnight_is_utc():
    now = datetime(2026, 11, 3, 18, 30, tzinfo=UTC)
    assert utc_midnight(now) == datetime(2026, 11, 3, 0, 0, tzinfo=UTC)


def test_slug_is_stable_and_safe():
    s = slug_for("https://Example.com/mcp")
    assert s == slug_for("https://Example.com/mcp") and s != slug_for("https://Example.com/other")
    assert s.startswith("c-") and all(ch.isalnum() or ch == "-" for ch in s)


def test_results_are_stored_published_and_hostile_rows_ignored(http_server, tmp_path):
    report = asyncio.run(scan(Target.from_url(http_server), ScanOptions(probes={"contract"})))
    out = tmp_path / "out"
    row = write_outputs(report, http_server, out)
    assert (out / f"{row['slug']}.html").exists() and row["kind"] == "community"

    data = tmp_path / "data"
    (data / "reports").mkdir(parents=True)
    for ext in ("html", "json", "svg"):
        (data / "reports" / f"{row['slug']}.{ext}").write_bytes((out / f"{row['slug']}.{ext}").read_bytes())
    merge_index(data, row)
    merge_index(data, row)   # same address again replaces, never duplicates
    rows = json.loads((data / "index.json").read_text())
    assert len(rows) == 1
    # hostile rows written to the data branch: path traversal slug, wrong types
    rows += [{"slug": "../../etc/passwd", "name": "x"}, {"slug": "ok-slug", "name": "<script>alert(1)</script>",
                                                          "score": "NaN", "grade": "Z"}, "junk", 5]
    (data / "index.json").write_text(json.dumps(rows))

    entries = tmp_path / "e.yaml"
    entries.write_text(yaml.safe_dump({"title": "T", "servers": [
        {"name": "Clean", "command": ["python3", str(submission.__file__).replace("src/mcpdoctor/submission.py",
                                                                                   "examples/servers/good_server.py")],
         "static_only": True}]}))
    site = tmp_path / "site"
    asyncio.run(leaderboard.build(entries, site, ScanOptions(call_timeout=5, time_budget_s=10), data))
    page = (site / "index.html").read_text()
    assert "community" in page and row["slug"] in page
    assert "<script>alert(1)" not in page and "../../etc" not in page
    assert (site / f"{row['slug']}.html").exists()
    assert "ok-slug" not in page   # no report file was stored for it, so it is not listed
