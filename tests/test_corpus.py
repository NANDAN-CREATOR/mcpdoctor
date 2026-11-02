"""Benchmark: the demo servers contain deliberately planted defects. The engine must find every one of them and
report nothing of MEDIUM severity or above on the clean server. Numbers printed here are quoted in the README."""
from __future__ import annotations

import pytest

from conftest import scan_server
from mcpdoctor.models import Severity

EXPECTED = {
    "bad_poisoned.py": {"S001", "S002", "S003", "S004", "S006"},
    "bad_files.py": {"D001", "D002", "D007"},
    "bad_sql.py": {"D003", "D004", "D005", "S005"},
    "bad_exec.py": {"D006", "S005", "D008", "S006"},
    "bad_quality.py": {"Q001", "Q002", "Q005", "Q006", "Q008", "Q009", "Q010", "Q011", "Q012", "B001", "B003",
                       "B004", "D009", "D010", "D011"},
    "bad_crash.py": {"P002"},
}
KW = {"probe_all": True, "slow_ms": 1000.0}


def test_clean_server_has_no_significant_findings():
    r = scan_server("good_server.py")
    bad = [f for f in r.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert not bad, [(f.rule_id, f.message) for f in bad]
    assert r.scores["overall"] >= 95


@pytest.mark.parametrize("name,expected", EXPECTED.items())
def test_planted_defects_are_found(name, expected):
    found = {f.rule_id for f in scan_server(name, **KW).findings}
    assert expected <= found, f"{name}: missed {sorted(expected - found)}"


@pytest.mark.parametrize("name", [n for n in EXPECTED if n != "bad_quality.py"])
def test_bad_servers_fail_the_default_gate(name):
    r = scan_server(name, **KW)
    assert any(f.severity.rank >= Severity.HIGH.rank for f in r.findings)
    assert r.scores["overall"] <= 84  # a high finding caps the score


def test_benchmark_summary(capsys):
    planted = sum(len(v) for v in EXPECTED.values())
    hit = sum(len(v & {f.rule_id for f in scan_server(n, **KW).findings}) for n, v in EXPECTED.items())
    noise = [f for f in scan_server("good_server.py").findings]
    with capsys.disabled():
        print(f"\nCORPUS: detected {hit}/{planted} planted defect classes; "
              f"{len(noise)} finding(s) on the clean server")
    assert hit == planted


def test_static_only_never_calls_tools():
    r = scan_server("bad_exec.py", static_only=True)
    assert r.evaluation.get("calls_made", 0) == 0
    assert "D006" not in {f.rule_id for f in r.findings}
    assert "S005" in {f.rule_id for f in r.findings}


def test_destructive_looking_tools_are_skipped_without_probe_all():
    r = scan_server("bad_exec.py")
    assert any(c.name == "contract" for c in r.coverage)
    assert "D006" in {f.rule_id for f in r.findings}  # ping_host is not destructive-looking, so it is probed
