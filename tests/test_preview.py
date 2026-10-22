"""Impact preview tests.

The previewer's promise is that it only reads. Every test here therefore checks
two things: the decision it reports, and that the directory is byte-identical
afterwards.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from acme_rehearsal.ca import LocalCA
from acme_rehearsal.guard import FilesystemGuard, diff_snapshots, directory_snapshot
from acme_rehearsal.preview import PRODUCTION_SERVERS, Previewer, _parse_days
from acme_rehearsal.rehearsal import Rehearsal, RehearsalConfig
from acme_rehearsal.store import CertStore


@pytest.fixture(scope="module")
def config_dir(tmp_path_factory) -> Path:
    """A realistic certbot config dir produced by a real rehearsal."""
    workdir = tmp_path_factory.mktemp("preview-src")
    config = RehearsalConfig(
        domains=["prod.example.test"], workdir=workdir, run_openssl=False
    )
    Rehearsal(config).run("issue")
    return workdir / "sandbox" / "etc"


def test_scan_finds_the_lineage(config_dir: Path) -> None:
    preview = Previewer(config_dir).scan()
    assert preview.exists is True
    assert len(preview.lineages) == 1
    assert preview.lineages[0]["domain"] == "prod.example.test"
    assert preview.lineages[0]["days_remaining"] is not None


def test_scan_reports_missing_directory_gracefully(tmp_path: Path) -> None:
    preview = Previewer(tmp_path / "absent").scan()
    assert preview.exists is False
    assert preview.warnings


def test_scan_warns_on_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    preview = Previewer(empty).scan()
    assert preview.exists is True
    assert any("no renewal configurations" in w for w in preview.warnings)


def test_renew_skips_certificate_outside_window(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_renew()
    assert preview.would_affect == []
    assert len(preview.would_skip) == 1
    assert preview.risk == "low"
    assert preview.quota_estimate["certificates_requested"] == 0


def test_force_renew_affects_everything(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_renew(force=True)
    assert len(preview.would_affect) == 1
    assert preview.would_affect[0]["reason"] == "forced"
    assert preview.risk == "medium"
    assert preview.quota_estimate["certificates_requested"] == 1
    assert any("weekly limit" in w for w in preview.warnings)


def test_renew_predicts_hook_environment(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_renew(force=True)
    env = preview.hook_environment[0]
    assert env["RENEWED_DOMAINS"] == "prod.example.test"
    assert env["RENEWED_LINEAGE"].endswith("live\\prod.example.test") or env[
        "RENEWED_LINEAGE"
    ].endswith("live/prod.example.test")


def test_renew_lists_files_that_would_be_written(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_renew(force=True)
    names = {Path(p).name for p in preview.files_touched}
    assert "cert2.pem" in names, "renewal should predict the next archive version"
    assert "cert.pem" in names, "live symlink target would be rewritten"


def test_revoke_flags_high_risk_and_names_impact(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_revoke()
    assert preview.risk == "high"
    assert len(preview.would_affect) == 1
    assert "TLS" in preview.would_affect[0]["impact"]
    assert any("not reversible" in w for w in preview.warnings)


def test_delete_lists_every_path(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_delete()
    assert preview.risk == "high"
    assert len(preview.files_touched) >= 10
    assert any(p.endswith("privkey1.pem") for p in preview.files_touched)
    assert any(p.endswith("prod.example.test.conf") for p in preview.files_touched)
    assert any("private key" in w for w in preview.warnings)


def test_expand_reports_added_domains(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_expand(["new.example.test", "prod.example.test"])
    entry = preview.would_affect[0]
    assert entry["added_domains"] == ["new.example.test"]
    assert entry["new_total"] == 2
    assert preview.quota_estimate["certificates_requested"] == 1


def test_expand_with_no_new_domains_requests_nothing(config_dir: Path) -> None:
    preview = Previewer(config_dir).preview_expand(["prod.example.test"])
    assert preview.would_affect[0]["added_domains"] == []
    assert preview.quota_estimate["certificates_requested"] == 0


# --------------------------------------------------------------------------
# Read-only guarantee
# --------------------------------------------------------------------------


@pytest.mark.parametrize("operation", ["renew", "renew-force", "revoke", "delete", "expand"])
def test_preview_never_modifies_the_directory(config_dir: Path, operation: str) -> None:
    before = directory_snapshot(config_dir)
    previewer = Previewer(config_dir)
    previewer.scan()
    if operation == "renew":
        previewer.preview_renew()
    elif operation == "renew-force":
        previewer.preview_renew(force=True)
    elif operation == "revoke":
        previewer.preview_revoke()
    elif operation == "delete":
        previewer.preview_delete()
    else:
        previewer.preview_expand(["x.example.test"])
    after = directory_snapshot(config_dir)
    assert diff_snapshots(before, after)["identical"] is True, (
        f"preview.{operation} mutated the config directory"
    )


# --------------------------------------------------------------------------
# Warnings
# --------------------------------------------------------------------------


def test_warns_when_server_is_production(tmp_path: Path) -> None:
    ca = LocalCA.create()
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    issued = ca.issue(key.public_key(), ["p.test"])
    root = tmp_path / "etc"
    root.mkdir()
    store = CertStore(root, FilesystemGuard(root))
    store.save_lineage(
        issued=issued,
        private_key_pem="k",
        server=PRODUCTION_SERVERS[0],
        account_id="a",
    )
    preview = Previewer(root).scan()
    assert any("production endpoint" in w for w in preview.warnings)


def test_warns_when_manual_authenticator_has_no_hook(tmp_path: Path) -> None:
    ca = LocalCA.create()
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    issued = ca.issue(key.public_key(), ["m.test"])
    root = tmp_path / "etc"
    root.mkdir()
    store = CertStore(root, FilesystemGuard(root))
    lineage = store.save_lineage(
        issued=issued,
        private_key_pem="k",
        server="http://127.0.0.1/directory",
        account_id="a",
        authenticator="manual",
    )
    preview = Previewer(root).scan()
    assert any("manual without an auth hook" in w for w in preview.warnings)
    assert lineage.config_path.exists()


def test_warns_when_chain_is_empty(tmp_path: Path) -> None:
    ca = LocalCA.create()
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    issued = ca.issue(key.public_key(), ["c.test"])
    root = tmp_path / "etc"
    root.mkdir()
    store = CertStore(root, FilesystemGuard(root))
    lineage = store.save_lineage(
        issued=issued, private_key_pem="k", server="http://x/directory", account_id="a"
    )
    (lineage.archive_dir / "chain1.pem").write_text("", encoding="utf-8")
    preview = Previewer(root).scan()
    assert any("chain.pem is empty" in w for w in preview.warnings)


def test_no_warning_for_single_intermediate_chain(config_dir: Path) -> None:
    """One intermediate is normal; warning about it would train users to ignore warnings."""
    preview = Previewer(config_dir).scan()
    assert not any("chain.pem is empty" in w for w in preview.warnings)


def test_expired_certificate_is_flagged(tmp_path: Path) -> None:
    ca = LocalCA.create()
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    issued = ca.issue(key.public_key(), ["e.test"], validity_days=1)
    root = tmp_path / "etc"
    root.mkdir()
    store = CertStore(root, FilesystemGuard(root))
    store.save_lineage(
        issued=issued, private_key_pem="k", server="http://x/directory", account_id="a"
    )
    future = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)
    preview = Previewer(root, now=future).scan()
    assert preview.lineages[0]["expired"] is True
    assert any("already expired" in w for w in preview.warnings)


# --------------------------------------------------------------------------
# Threshold parsing
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30 days", 30),
        ("1 day", 1),
        ("10 days", 10),
        ("48 hours", 2),
        ("nonsense", 30),
    ],
)
def test_parse_days(text: str, expected: int) -> None:
    assert _parse_days(text, default=30) == expected
