"""Runs the real scripts/submission.py against a fake GitHub API, to check the gate/limits/publish flow end to end."""
from __future__ import annotations

import importlib.util
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from mcpdoctor.submission import SubmissionError

ROOT = Path(__file__).resolve().parent.parent
BODY = ("### MCP server address\n\nhttps://example.com/mcp\n\n### Permission\n\n"
        "- [X] I own this server, or I have permission to test it.\n")


class FakeGitHub(BaseHTTPRequestHandler):
    issues: list[dict] = []
    calls: list[tuple[str, str, dict]] = []

    def log_message(self, *a):
        pass

    def _reply(self, payload):
        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        FakeGitHub.calls.append(("GET", self.path, {}))
        self._reply(FakeGitHub.issues)

    def _write(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else {}
        FakeGitHub.calls.append((self.command, self.path, body))
        self._reply({})

    do_POST = do_PATCH = _write


@pytest.fixture()
def glue(monkeypatch, tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    FakeGitHub.issues, FakeGitHub.calls = [], []
    out = tmp_path / "gh_output"
    for k, v in {"GITHUB_API_URL": f"http://127.0.0.1:{srv.server_address[1]}", "GH_TOKEN": "t", "REPO": "NANDAN-CREATOR/mcpdoctor",
                 "ISSUE_NUMBER": "7", "ISSUE_USER": "alice", "ISSUE_BODY": BODY, "GITHUB_OUTPUT": str(out)}.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location("submission_glue", ROOT / "scripts" / "submission.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "validate_server_url", lambda raw: raw)   # no DNS in tests
    monkeypatch.chdir(tmp_path)
    yield mod, out
    srv.shutdown()


def _today_issue(user):
    return {"user": {"login": user}, "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _comments():
    return [c[2]["body"] for c in FakeGitHub.calls if c[0] == "POST" and c[1].endswith("/comments")]


def test_request_is_accepted_when_under_the_limit(glue):
    mod, out = glue
    FakeGitHub.issues = [_today_issue("bob")] * 4          # 4 of 5 used
    mod.cmd_gate()
    assert "accepted=true" in out.read_text()
    labels = [c[2]["labels"] for c in FakeGitHub.calls if c[1].endswith("/labels")]
    assert ["scan-accepted"] in labels and not any(c[0] == "PATCH" for c in FakeGitHub.calls)


def test_sixth_request_of_the_day_is_rejected_and_closed(glue):
    mod, out = glue
    FakeGitHub.issues = [_today_issue(u) for u in "abcde"]   # 5 of 5 used
    mod.cmd_gate()
    assert "accepted=false" in out.read_text()
    assert any("daily limit of 5" in c for c in _comments())
    assert any(c[0] == "PATCH" and c[2]["state"] == "closed" for c in FakeGitHub.calls)
    assert ["scan-rejected"] in [c[2]["labels"] for c in FakeGitHub.calls if c[1].endswith("/labels")]


def test_yesterdays_requests_do_not_count(glue):
    mod, out = glue
    old = {"user": {"login": "x"}, "created_at": "2020-01-01T10:00:00Z"}
    FakeGitHub.issues = [old] * 9
    mod.cmd_gate()
    assert "accepted=true" in out.read_text()


def test_pull_requests_in_the_issue_list_are_not_counted(glue):
    mod, out = glue
    FakeGitHub.issues = [{**_today_issue("x"), "pull_request": {}}] * 9
    mod.cmd_gate()
    assert "accepted=true" in out.read_text()


def test_missing_consent_is_rejected(glue, monkeypatch):
    mod, out = glue
    monkeypatch.setenv("ISSUE_BODY", BODY.replace("[X]", "[ ]"))
    mod.cmd_gate()
    assert "accepted=false" in out.read_text() and any("tick the box" in c for c in _comments())


def test_unsafe_address_is_rejected_with_a_reason(glue, monkeypatch):
    mod, out = glue

    def refuse(raw):
        raise SubmissionError("Local and internal addresses cannot be tested here.")
    monkeypatch.setattr(mod, "validate_server_url", refuse)
    mod.cmd_gate()
    assert "accepted=false" in out.read_text() and any("internal addresses" in c for c in _comments())


def test_per_person_limit(glue):
    mod, out = glue
    FakeGitHub.issues = [_today_issue("alice")] * 2
    mod.cmd_gate()
    assert "accepted=false" in out.read_text() and any("2 tests for today" in c for c in _comments())


def test_publish_reports_failure_when_scan_produced_nothing(glue, tmp_path):
    mod, _ = glue
    mod.cmd_publish()   # no submission-out directory at all (job cancelled/timed out)
    assert any("could not be completed" in c for c in _comments())
    assert ["scan-failed"] in [c[2]["labels"] for c in FakeGitHub.calls if c[1].endswith("/labels")]
