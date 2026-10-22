"""Report rendering tests.

Escaping gets explicit coverage: the report embeds certificate subjects and
transcript strings that originate from data, and an unescaped ``<script>`` in a
subject would execute in the reviewer's browser.
"""

from __future__ import annotations

from pathlib import Path

from acme_rehearsal.report import collect_artifacts, render_index, render_report, write_report


def _transcript(**overrides) -> dict:
    base = {
        "schema": "acme-rehearsal/1",
        "scenario": "issue",
        "started_at": "2026-10-22T00:00:00+00:00",
        "finished_at": "2026-10-22T00:00:01+00:00",
        "duration_ms": 1000.0,
        "inputs": {"domains": ["a.test"], "challenge_type": "http-01"},
        "steps": [
            {
                "index": 1,
                "phase": "setup",
                "action": "create-local-ca",
                "status": "ok",
                "duration_ms": 1.0,
                "output": {"root": "x"},
            },
            {
                "index": 2,
                "phase": "acme",
                "action": "new-order",
                "status": "ok",
                "duration_ms": 2.0,
                "input": {"identifiers": ["a.test"]},
            },
        ],
        "containment": {
            "egress": {
                "total_attempts": 3,
                "blocked_count": 0,
                "outbound_connections": 3,
                "attempts": [
                    {"kind": "connect", "target": "127.0.0.1", "allowed": True, "reason": "loopback"}
                ],
            },
            "filesystem": {"root": "/sandbox", "enforced": True, "write_count": 2, "writes": []},
            "real_config_snapshot": {"identical": True, "file_count": 4, "added": [], "removed": [], "changed": []},
        },
        "result": {
            "certificate": {
                "subject": "CN=a.test",
                "issuer": "CN=Rehearsal Sandbox Intermediate CA",
                "sans": ["a.test"],
                "not_after": "2027-01-20T00:00:00+00:00",
                "sha256": "ab" * 32,
            },
            "lineage": {"domain": "a.test", "version": 1, "link_mode": "copy"},
            "error": None,
        },
        "notes": [],
        "verdict": {
            "passed": True,
            "checks": [
                {"name": "no_egress", "passed": True, "detail": "0 blocked"},
                {"name": "sandbox_writes_only", "passed": True, "detail": "2 writes"},
            ],
        },
    }
    base.update(overrides)
    return base


def test_report_contains_all_three_sections() -> None:
    html = render_report(_transcript())
    assert "输入 · 本次模拟了什么" in html
    assert "执行过程 · 逐步" in html
    assert "结果 · 签发的证书" in html
    assert "隔离证据" in html


def test_report_shows_pass_verdict() -> None:
    html = render_report(_transcript())
    assert "verdict pass" in html
    assert "CONTAINED" in html


def test_report_shows_fail_verdict() -> None:
    transcript = _transcript()
    transcript["verdict"] = {
        "passed": False,
        "checks": [{"name": "no_egress", "passed": False, "detail": "1 blocked"}],
    }
    html = render_report(transcript)
    assert "verdict fail" in html
    assert "VERDICT FAILED" in html


def test_report_renders_every_step() -> None:
    html = render_report(_transcript())
    assert "create-local-ca" in html
    assert "new-order" in html


def test_report_renders_certificate_fields() -> None:
    html = render_report(_transcript())
    assert "CN=a.test" in html
    assert "ab" * 32 in html


def test_report_renders_error_note_for_failure_scenario() -> None:
    transcript = _transcript(scenario="failure-badcsr")
    transcript["result"]["error"] = {
        "type": "badCSR",
        "detail": "CSR requests identifiers not present in the order",
        "urn": "urn:ietf:params:acme:error:badCSR",
        "status": 400,
    }
    html = render_report(transcript)
    assert "badCSR" in html
    assert "按设计在 ACME 层失败" in html


def test_report_renders_notes() -> None:
    transcript = _transcript()
    transcript["notes"] = ["live/ entries are copies rather than symlinks"]
    html = render_report(transcript)
    assert "live/ entries are copies" in html


# --------------------------------------------------------------------------
# Escaping
# --------------------------------------------------------------------------


def test_html_in_certificate_subject_is_escaped() -> None:
    transcript = _transcript()
    transcript["result"]["certificate"]["subject"] = "<script>alert(1)</script>"
    html = render_report(transcript)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_in_step_action_is_escaped() -> None:
    transcript = _transcript()
    transcript["steps"][0]["action"] = "<img src=x onerror=alert(1)>"
    html = render_report(transcript)
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


def test_html_in_notes_is_escaped() -> None:
    transcript = _transcript()
    transcript["notes"] = ['"><script>x</script>']
    html = render_report(transcript)
    assert "<script>x</script>" not in html


def test_quotes_in_attributes_are_escaped() -> None:
    transcript = _transcript()
    transcript["scenario"] = 'a" onmouseover="alert(1)'
    html = render_report(transcript)
    assert 'onmouseover="alert(1)"' not in html


# --------------------------------------------------------------------------
# Robustness
# --------------------------------------------------------------------------


def test_report_survives_minimal_transcript() -> None:
    html = render_report({"scenario": "x", "verdict": {"passed": True, "checks": []}})
    assert "<html" in html
    assert "ACME 演练报告" in html


def test_report_handles_missing_snapshot() -> None:
    transcript = _transcript()
    transcript["containment"]["real_config_snapshot"] = None
    html = render_report(transcript)
    assert "未涉及" in html


def test_long_values_are_clipped() -> None:
    transcript = _transcript()
    transcript["steps"][0]["output"] = {"blob": "x" * 5000}
    html = render_report(transcript)
    assert "chars clipped" in html


def test_write_report_creates_file(tmp_path: Path) -> None:
    path = write_report(_transcript(), tmp_path / "out" / "report.html")
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


# --------------------------------------------------------------------------
# Artifacts and index
# --------------------------------------------------------------------------


def test_collect_artifacts_lists_tree(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.txt").write_text("x", encoding="utf-8")
    entries = collect_artifacts(tmp_path)
    assert "a/" in entries
    assert "a/b.txt" in entries


def test_collect_artifacts_of_missing_dir_is_empty(tmp_path: Path) -> None:
    assert collect_artifacts(tmp_path / "nope") == []


def test_index_lists_every_scenario() -> None:
    rows = [
        {"scenario": "issue", "passed": True, "duration_ms": 10, "steps": 5, "report": "report.html", "dir": "issue", "checks": []},
        {"scenario": "renew", "passed": False, "duration_ms": 20, "steps": 6, "report": "report.html", "dir": "renew", "checks": []},
    ]
    html = render_index(rows)
    assert "issue" in html
    assert "renew" in html
    assert "SOME SCENARIOS FAILED" in html


def test_index_all_pass_message() -> None:
    rows = [
        {"scenario": "issue", "passed": True, "duration_ms": 1, "steps": 1, "report": "report.html", "dir": "issue", "checks": []}
    ]
    assert "ALL SCENARIOS CONTAINED" in render_index(rows)


def test_index_summarises_checks_across_scenarios() -> None:
    rows = [
        {
            "scenario": "a", "passed": True, "duration_ms": 1, "steps": 1,
            "report": "r.html", "dir": "a",
            "checks": [{"name": "no_egress", "passed": True}, {"name": "chain_verifies", "passed": True}],
        },
        {
            "scenario": "b", "passed": True, "duration_ms": 1, "steps": 1,
            "report": "r.html", "dir": "b",
            "checks": [{"name": "no_egress", "passed": True}],
        },
    ]
    html = render_index(rows)
    assert "no_egress" in html
    assert "2/2" in html
    assert "1/1" in html
