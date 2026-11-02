"""Drives the on-page submission form in a real browser with the network mocked."""
from __future__ import annotations

import json

import pytest

from mcpdoctor.leaderboard import _index

sync_api = pytest.importorskip("playwright.sync_api")
CFG = {"submit_api": "https://w.example.workers.dev", "turnstile_sitekey": "0x4AAAAAAAbcdef"}


def _run(tmp_path, comments_body, worker_status=200, worker_body=None):
    page_file = tmp_path / "index.html"
    page_file.write_text(_index("T", [], CFG))
    sent = {}
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception:
            pytest.skip("no browser available")
        pg = browser.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.route("https://challenges.cloudflare.com/**", lambda r: r.fulfill(status=200, content_type="text/javascript", body=""))
        cors = {"access-control-allow-origin": "*", "access-control-allow-headers": "content-type"}

        def worker(route):
            if route.request.method == "OPTIONS":
                return route.fulfill(status=204, headers=cors)
            sent.update(json.loads(route.request.post_data))
            return route.fulfill(status=worker_status, content_type="application/json", headers=cors,
                                 body=json.dumps(worker_body or {"ok": True, "issue": 42}))

        pg.route("https://w.example.workers.dev/**", worker)
        pg.route("https://api.github.com/**", lambda r: r.fulfill(status=200, content_type="application/json", headers=cors,
                                                                   body=json.dumps(comments_body)))
        pg.goto(page_file.as_uri())
        pg.fill("input[name=url]", "https://example.com/mcp")
        pg.check("input[name=consent]")
        pg.click("button[type=submit]")
        pg.wait_for_function("!/Sending|Testing/.test(document.getElementById('sf-out').textContent)", timeout=30000)
        text = pg.inner_text("#sf-out")
        href = pg.get_attribute("#sf-out a", "href") if pg.query_selector("#sf-out a") else None
        browser.close()
    assert not errors, errors
    return sent, text, href


def test_success_shows_score_and_report_link(tmp_path):
    sent, text, href = _run(tmp_path, [{"body": "## Result: 83/100, grade B\n\nFull report (appears within about two minutes): "
                                               "https://nandan-creator.github.io/mcpdoctor/c-example-com-abc123.html"}])
    assert sent == {"url": "https://example.com/mcp", "consent": True, "token": ""}
    assert "83/100" in text and href == "https://nandan-creator.github.io/mcpdoctor/c-example-com-abc123.html"


def test_rejection_reason_is_shown(tmp_path):
    _, text, _ = _run(tmp_path, [{"body": "Sorry, this request was not accepted.\n\n**Reason:** The daily limit of 5 tests has been reached."}])
    assert "daily limit of 5" in text


def test_service_error_is_shown_and_no_polling(tmp_path):
    _, text, _ = _run(tmp_path, [], worker_status=400, worker_body={"error": "The spam check failed."})
    assert "spam check failed" in text


def test_a_hostile_comment_cannot_inject_a_link_or_html(tmp_path):
    evil = ('Full report <a href="javascript:alert(1)">x</a> https://evil.example/c-x.html '
            "Result: 99/100, grade A")
    _, text, href = _run(tmp_path, [{"body": evil}])
    assert href is None            # only links on our own domain are ever rendered
    assert "<a" not in text or "javascript:" not in text
