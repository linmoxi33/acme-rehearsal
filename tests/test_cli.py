"""CLI tests.

Exit codes are part of the contract: the command is meant to be usable as a CI
gate, so 0 means "the rehearsal was contained and behaved as expected".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acme_rehearsal.cli import main


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "acme-rehearsal" in capsys.readouterr().out


def test_missing_command_is_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_issue_run_returns_zero(tmp_path: Path, capsys) -> None:
    code = main(
        [
            "run",
            "--scenario",
            "issue",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "PASSED" in out
    assert "no_egress" in out
    assert (tmp_path / "w" / "report.html").exists()


def test_failure_scenario_still_returns_zero(tmp_path: Path) -> None:
    """A fault-injection scenario is a success when the fault appears as designed."""
    code = main(
        [
            "run",
            "--scenario",
            "failure-badcsr",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
        ]
    )
    assert code == 0


def test_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
    main(
        [
            "run",
            "--scenario",
            "failure-http01",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "acme-rehearsal/1"
    assert payload["verdict"]["passed"] is True
    assert payload["result"]["error"]["type"] == "unauthorized"


def test_quiet_mode_prints_one_line(tmp_path: Path, capsys) -> None:
    main(
        [
            "run",
            "--scenario",
            "issue",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
            "--quiet",
        ]
    )
    assert capsys.readouterr().out.strip() == "PASSED"


def test_verify_reads_a_transcript(tmp_path: Path, capsys) -> None:
    main(
        [
            "run",
            "--scenario",
            "issue",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
            "--quiet",
        ]
    )
    capsys.readouterr()
    code = main(["verify", "--transcript", str(tmp_path / "w" / "transcript.json")])
    assert code == 0
    assert "PASSED" in capsys.readouterr().out


def test_verify_json(tmp_path: Path, capsys) -> None:
    main(
        [
            "run",
            "--scenario",
            "issue",
            "--workdir",
            str(tmp_path / "w"),
            "--no-openssl",
            "--quiet",
        ]
    )
    capsys.readouterr()
    main(
        [
            "verify",
            "--transcript",
            str(tmp_path / "w" / "transcript.json"),
            "--json",
        ]
    )
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["passed"] is True


def test_verify_fails_on_tampered_transcript(tmp_path: Path, capsys) -> None:
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps(
            {
                "schema": "acme-rehearsal/1",
                "scenario": "issue",
                "verdict": {"passed": False, "checks": [{"name": "no_egress", "passed": False}]},
            }
        ),
        encoding="utf-8",
    )
    assert main(["verify", "--transcript", str(path)]) == 1


# --------------------------------------------------------------------------
# Preview
# --------------------------------------------------------------------------


@pytest.fixture
def preview_config(tmp_path: Path) -> Path:
    from acme_rehearsal.rehearsal import Rehearsal, RehearsalConfig

    config = RehearsalConfig(
        domains=["p.test"], workdir=tmp_path / "src", run_openssl=False
    )
    Rehearsal(config).run("issue")
    return tmp_path / "src" / "sandbox" / "etc"


def test_preview_renew(preview_config: Path, capsys) -> None:
    assert main(["preview", "--config-dir", str(preview_config), "--operation", "renew"]) == 0
    out = capsys.readouterr().out
    assert "lineage" in out
    assert "只读" in out


def test_preview_json(preview_config: Path, capsys) -> None:
    main(
        [
            "preview",
            "--config-dir",
            str(preview_config),
            "--operation",
            "delete",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["preview"]["risk"] == "high"
    assert payload["preview"]["files_touched"]


def test_preview_expand(preview_config: Path, capsys) -> None:
    main(
        [
            "preview",
            "--config-dir",
            str(preview_config),
            "--operation",
            "expand",
            "--add-domain",
            "new.test",
        ]
    )
    assert "new.test" in capsys.readouterr().out


def test_preview_reports_missing_dir(tmp_path: Path, capsys) -> None:
    code = main(["preview", "--config-dir", str(tmp_path / "absent"), "--operation", "renew"])
    assert code == 0
    out = capsys.readouterr().out
    assert "does not exist" in out or "不存在" in out


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------


def test_demo_runs_all_scenarios(tmp_path: Path, capsys) -> None:
    code = main(["demo", "--workdir", str(tmp_path / "demo"), "--no-openssl"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.count("PASS") == 6
    assert (tmp_path / "demo" / "index.html").exists()
    assert (tmp_path / "demo" / "issue" / "report.html").exists()
