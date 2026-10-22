"""End-to-end rehearsal tests.

These exercise the whole stack: CA, server, client, challenges, storage, guards
and the transcript. The central assertion is not "a certificate appeared" but
"nothing outside the sandbox changed".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acme_rehearsal.rehearsal import SCENARIOS, Rehearsal, RehearsalConfig


@pytest.fixture(scope="module")
def issue_outcome(tmp_path_factory):
    """One issuance shared by the read-only assertions (issuance is ~1s)."""
    workdir = tmp_path_factory.mktemp("issue")
    config = RehearsalConfig(
        domains=["demo.example.test"], workdir=workdir, run_openssl=False
    )
    return Rehearsal(config).run("issue")


def test_issue_scenario_passes(issue_outcome) -> None:
    assert issue_outcome.passed, issue_outcome.transcript["verdict"]


def test_issue_produces_a_parseable_certificate(issue_outcome) -> None:
    cert = issue_outcome.transcript["result"]["certificate"]
    assert cert["sans"] == ["demo.example.test"]
    assert cert["issuer"].startswith("CN=Rehearsal Sandbox Intermediate CA")
    assert len(cert["sha256"]) == 64


def test_issue_writes_certbot_layout(issue_outcome) -> None:
    workdir = Path(issue_outcome.workdir)
    live = workdir / "sandbox" / "etc" / "live" / "demo.example.test"
    assert (live / "cert.pem").exists()
    assert (live / "fullchain.pem").exists()
    assert (workdir / "sandbox" / "etc" / "renewal" / "demo.example.test.conf").exists()


def test_issue_records_every_step_in_order(issue_outcome) -> None:
    steps = issue_outcome.transcript["steps"]
    actions = [s["action"] for s in steps]
    assert actions[0] == "create-local-ca"
    for required in (
        "fetch-directory",
        "new-account",
        "new-order",
        "publish-response",
        "trigger-validation",
        "finalize",
        "download-certificate",
        "walk-chain",
        "write-lineage",
    ):
        assert required in actions, f"missing step {required}"
    assert [s["index"] for s in steps] == list(range(1, len(steps) + 1))


def test_issue_has_zero_blocked_egress(issue_outcome) -> None:
    egress = issue_outcome.transcript["containment"]["egress"]
    assert egress["blocked_count"] == 0
    assert egress["verdict"] == "no-egress"
    non_loopback = [
        a for a in egress["attempts"] if a["allowed"] and a["reason"] != "loopback"
    ]
    assert non_loopback == []


def test_issue_writes_stay_inside_sandbox(issue_outcome) -> None:
    filesystem = issue_outcome.transcript["containment"]["filesystem"]
    root = Path(filesystem["root"]).resolve()
    assert filesystem["write_count"] > 0
    for entry in filesystem["writes"]:
        assert Path(entry["path"]).resolve().is_relative_to(root)


def test_transcript_is_written_to_disk(issue_outcome) -> None:
    path = Path(issue_outcome.transcript_path)
    assert path.exists()
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded["schema"] == "acme-rehearsal/1"
    assert reloaded["verdict"]["passed"] is True


def test_no_public_ca_hostname_was_contacted(issue_outcome) -> None:
    checks = {c["name"]: c for c in issue_outcome.transcript["verdict"]["checks"]}
    assert checks["no_public_ca_contact"]["passed"] is True


# --------------------------------------------------------------------------
# Real config directory must remain byte-identical
# --------------------------------------------------------------------------


def test_real_config_dir_is_untouched(tmp_path: Path) -> None:
    """The headline guarantee, asserted on hashes rather than on intent."""
    real = tmp_path / "real-letsencrypt"
    (real / "renewal").mkdir(parents=True)
    (real / "live" / "prod.test").mkdir(parents=True)
    (real / "renewal" / "prod.test.conf").write_text(
        "version = 5.8.0\n[renewalparams]\nserver = https://acme-v02.api.letsencrypt.org/directory\n",
        encoding="utf-8",
    )
    (real / "live" / "prod.test" / "cert.pem").write_text("PRECIOUS", encoding="utf-8")

    before = {
        p.relative_to(real).as_posix(): p.read_bytes()
        for p in real.rglob("*")
        if p.is_file()
    }

    config = RehearsalConfig(
        domains=["demo.example.test"],
        workdir=tmp_path / "work",
        run_openssl=False,
        real_config_dir=real,
    )
    outcome = Rehearsal(config).run("issue")

    after = {
        p.relative_to(real).as_posix(): p.read_bytes()
        for p in real.rglob("*")
        if p.is_file()
    }
    assert before == after, "rehearsal modified a real config directory"

    snapshot = outcome.transcript["containment"]["real_config_snapshot"]
    assert snapshot["identical"] is True
    assert snapshot["file_count"] == 2
    checks = {c["name"]: c for c in outcome.transcript["verdict"]["checks"]}
    assert checks["real_config_untouched"]["passed"] is True


# --------------------------------------------------------------------------
# Renewal
# --------------------------------------------------------------------------


def test_renew_creates_a_second_archive_version(tmp_path: Path) -> None:
    config = RehearsalConfig(
        domains=["demo.example.test"], workdir=tmp_path / "work", run_openssl=False
    )
    outcome = Rehearsal(config).run("renew")
    assert outcome.passed, outcome.transcript["verdict"]
    archive = tmp_path / "work" / "sandbox" / "etc" / "archive" / "demo.example.test"
    assert (archive / "cert1.pem").exists()
    assert (archive / "cert2.pem").exists()
    assert outcome.transcript["result"]["lineage"]["version"] == 2


def test_renew_issues_short_lived_certificate_first(tmp_path: Path) -> None:
    """The first cert must be inside the renewal window or renew would skip it."""
    config = RehearsalConfig(
        domains=["demo.example.test"], workdir=tmp_path / "work", run_openssl=False
    )
    outcome = Rehearsal(config).run("renew")
    steps = {s["action"]: s for s in outcome.transcript["steps"]}
    preview = steps["preview-impact"]["output"]
    assert preview["would_affect"], "renewal preview reported nothing to renew"
    assert preview["would_affect"][0]["days_remaining"] <= 30


# --------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------


def test_revoke_scenario_records_crl_entry(tmp_path: Path) -> None:
    config = RehearsalConfig(
        domains=["demo.example.test"], workdir=tmp_path / "work", run_openssl=False
    )
    outcome = Rehearsal(config).run("revoke")
    assert outcome.passed, outcome.transcript["verdict"]
    confirm = [s for s in outcome.transcript["steps"] if s["action"] == "confirm-crl"][0]
    assert len(confirm["output"]["revoked_serials"]) == 1
    assert confirm["output"]["crl_blocks"] == 1


# --------------------------------------------------------------------------
# Failure scenarios
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("failure-http01", "unauthorized"),
        ("failure-ratelimit", "rateLimited"),
        ("failure-badcsr", "badCSR"),
    ],
)
def test_failure_scenarios_surface_expected_error(
    scenario: str, expected: str, tmp_path: Path
) -> None:
    config = RehearsalConfig(
        domains=["demo.example.test"],
        workdir=tmp_path / scenario,
        run_openssl=False,
    )
    outcome = Rehearsal(config).run(scenario)
    error = outcome.transcript["result"]["error"]
    assert error is not None, f"{scenario} did not raise an ACME error"
    assert error["type"] == expected
    assert error["urn"] == f"urn:ietf:params:acme:error:{expected}"


@pytest.mark.parametrize(
    "scenario", ["failure-http01", "failure-ratelimit", "failure-badcsr"]
)
def test_failure_scenarios_remain_contained(scenario: str, tmp_path: Path) -> None:
    """A failing operation must still be a contained operation."""
    config = RehearsalConfig(
        domains=["demo.example.test"],
        workdir=tmp_path / scenario,
        run_openssl=False,
    )
    outcome = Rehearsal(config).run(scenario)
    egress = outcome.transcript["containment"]["egress"]
    assert egress["blocked_count"] == 0
    checks = {c["name"]: c for c in outcome.transcript["verdict"]["checks"]}
    assert checks["expected_error_observed"]["passed"] is True


def test_badcsr_scenario_produces_no_lineage(tmp_path: Path) -> None:
    """If finalize fails, no certificate may be written."""
    config = RehearsalConfig(
        domains=["demo.example.test"],
        workdir=tmp_path / "work",
        run_openssl=False,
    )
    Rehearsal(config).run("failure-badcsr")
    renewal = tmp_path / "work" / "sandbox" / "etc" / "renewal"
    assert not renewal.exists() or list(renewal.glob("*.conf")) == []


def test_ratelimit_scenario_fails_on_order_not_on_validation(tmp_path: Path) -> None:
    config = RehearsalConfig(
        domains=["demo.example.test"],
        workdir=tmp_path / "work",
        run_openssl=False,
    )
    outcome = Rehearsal(config).run("failure-ratelimit")
    actions = [s["action"] for s in outcome.transcript["steps"]]
    # The limit must bite at order creation, before any challenge is attempted.
    assert "new-order" in actions
    assert "fetch-authorization" not in actions


# --------------------------------------------------------------------------
# Scenario registry
# --------------------------------------------------------------------------


def test_all_declared_scenarios_are_runnable(tmp_path: Path) -> None:
    """A name in SCENARIOS that raises ValueError would be a broken promise."""
    from acme_rehearsal.rehearsal import Rehearsal

    for scenario in SCENARIOS:
        config = RehearsalConfig(workdir=tmp_path / scenario, run_openssl=False)
        Rehearsal(config).run(scenario)  # must not raise


def test_unknown_scenario_is_rejected(tmp_path: Path) -> None:
    config = RehearsalConfig(workdir=tmp_path / "x", run_openssl=False)
    with pytest.raises(ValueError, match="unknown scenario"):
        Rehearsal(config).run("not-a-scenario")
