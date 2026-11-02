"""GitHub glue for community submissions. Called from .github/workflows/scan-request.yml.

    gate     validate the request, apply the daily limits, label the issue, write step outputs
    scan     run MCPDoctor against the (already validated) address and write result files
    publish  store the result on the data branch, comment on the issue, close it

All untrusted text (issue body, address) arrives through environment variables, never through shell interpolation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcpdoctor import __version__
from mcpdoctor.leaderboard import _clean_row
from mcpdoctor.runner import ScanOptions, scan
from mcpdoctor.submission import (
    DAILY_LIMIT,
    PER_USER_LIMIT,
    SubmissionError,
    decide,
    merge_index,
    read_request,
    utc_midnight,
    validate_server_url,
    write_outputs,
)
from mcpdoctor.target import Target

OUT = Path("submission-out")
SITE = "https://nandan-creator.github.io/mcpdoctor"


def api(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    req = urllib.request.Request(
        f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com')}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "mcpdoctor-submissions"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"GitHub API {method} {path} failed: HTTP {exc.code}") from exc
    return json.loads(text) if text else None


def comment(repo: str, number: str, text: str) -> None:
    api("POST", f"/repos/{repo}/issues/{number}/comments", {"body": text})


def close(repo: str, number: str, label: str) -> None:
    api("POST", f"/repos/{repo}/issues/{number}/labels", {"labels": [label]})
    api("PATCH", f"/repos/{repo}/issues/{number}", {"state": "closed", "state_reason": "completed"})


def set_output(**values: str) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
        for k, v in values.items():
            fh.write(f"{k}={v}\n")


def accepted_today(repo: str) -> list[dict[str, str]]:
    midnight = utc_midnight(datetime.now(UTC))
    issues = api("GET", f"/repos/{repo}/issues?labels=scan-accepted&state=all&per_page=100"
                        f"&since={midnight.strftime('%Y-%m-%dT%H:%M:%SZ')}") or []
    out = []
    for i in issues:
        if "pull_request" in i:
            continue
        created = datetime.fromisoformat(i["created_at"].replace("Z", "+00:00"))
        if created >= midnight:
            out.append({"user": (i.get("user") or {}).get("login", "")})
    return out


def cmd_gate() -> None:
    repo, number, user = os.environ["REPO"], os.environ["ISSUE_NUMBER"], os.environ["ISSUE_USER"]
    owner = repo.split("/")[0]
    try:
        raw_url, consent = read_request(os.environ.get("ISSUE_BODY", ""))
        if not consent:
            raise SubmissionError("Please tick the box confirming that you own this server or have permission to test it.")
        url = validate_server_url(raw_url)
        decision = decide(accepted_today(repo), user, owner)
        if not decision.allowed:
            raise SubmissionError(decision.reason)
    except SubmissionError as exc:
        comment(repo, number, f"Sorry, this request was not accepted.\n\n**Reason:** {exc}\n\nThe rules are listed on "
                              f"the [leaderboard page]({SITE}/#submit).")
        close(repo, number, "scan-rejected")
        set_output(accepted="false", url="")
        return
    api("POST", f"/repos/{repo}/issues/{number}/labels", {"labels": ["scan-accepted"]})
    comment(repo, number, f"Request accepted. Testing `{url}` now. This usually takes one to three minutes.")
    set_output(accepted="true", url=url)


def cmd_scan() -> None:
    url = validate_server_url(os.environ["SERVER_URL"])  # validated again: this job must not trust the previous one
    OUT.mkdir(exist_ok=True)
    opts = ScanOptions(max_calls=150, time_budget_s=120, call_timeout=15, init_timeout=30, repeats=2)
    report = asyncio.run(scan(Target.from_url(url), opts))
    if not report.tools:
        reasons = "; ".join(f.message for f in report.findings[:2]) or "no tools were returned"
        (OUT / "status.json").write_text(json.dumps({"ok": False, "error": reasons[:500]}))
        print("scan produced no tools:", reasons)
        return
    row = write_outputs(report, url, OUT)
    (OUT / "status.json").write_text(json.dumps({"ok": True, "slug": row["slug"]}))
    print(f"score {row['score']} ({row['grade']}) tools={row['tools']}")


def cmd_publish() -> None:
    repo, number = os.environ["REPO"], os.environ["ISSUE_NUMBER"]
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    try:
        status = json.loads((OUT / "status.json").read_text())
    except (OSError, ValueError):
        status = {"ok": False, "error": "the test did not finish (it may have timed out)"}
    if not status.get("ok"):
        comment(repo, number, "The test could not be completed, so nothing was published.\n\n"
                              f"**Details:** {str(status.get('error', ''))[:400]}\n\nCheck that the address is a public MCP "
                              "server using the Streamable HTTP transport, then open a new request.")
        close(repo, number, "scan-failed")
        return
    row = _clean_row(json.loads((OUT / "row.json").read_text()))
    slug = str(status.get("slug", ""))
    if row is None or row["slug"] != slug:
        comment(repo, number, "The result was rejected by validation and not published.")
        close(repo, number, "scan-failed")
        return
    (data_dir / "reports").mkdir(parents=True, exist_ok=True)
    for ext in ("html", "json", "svg"):
        src = OUT / f"{slug}.{ext}"
        if src.is_file():
            (data_dir / "reports" / f"{slug}.{ext}").write_bytes(src.read_bytes())
    merge_index(data_dir, row)
    crit_high = row["critical"] + row["high"]
    comment(repo, number,
            f"## Result: {row['score']}/100, grade {row['grade']}\n\n"
            f"| Security | Quality | Reliability | Serious issues |\n|---|---|---|---|\n"
            f"| {row['security'] if row['security'] is not None else '-'} | {row['quality']} | {row['reliability']} | {crit_high} |\n\n"
            f"Full report (appears within about two minutes): {SITE}/{slug}.html\n\n"
            f"It will also be listed on the [leaderboard]({SITE}/). Results are public. To remove yours, open an issue asking "
            f"for removal.\n\n_MCPDoctor {__version__}. Limits: {DAILY_LIMIT} tests per day in total, {PER_USER_LIMIT} per person._")
    close(repo, number, "scan-done")


if __name__ == "__main__":
    {"gate": cmd_gate, "scan": cmd_scan, "publish": cmd_publish}[sys.argv[1]]()
