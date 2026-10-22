"""Storage tests.

The renewal-config parser gets its own coverage because certbot's format is not
valid INI: top-level keys appear before any section header, which ``configparser``
rejects outright. A parser that only handles ``[renewalparams]`` would silently
lose ``cert``/``archive_dir`` and mis-report every lineage path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acme_rehearsal.ca import LocalCA
from acme_rehearsal.guard import FilesystemGuard, PathEscape
from acme_rehearsal.store import CertStore, _parse_renewal_config


@pytest.fixture
def store(tmp_path: Path) -> CertStore:
    root = tmp_path / "etc"
    root.mkdir()
    return CertStore(root, FilesystemGuard(root))


@pytest.fixture
def issued():
    ca = LocalCA.create()
    key = __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"])
    leaf = key.generate_private_key(public_exponent=65537, key_size=2048)
    return ca.issue(leaf.public_key(), ["a.test"], validity_days=30)


# --------------------------------------------------------------------------
# Renewal config parsing
# --------------------------------------------------------------------------


def test_parser_reads_top_level_keys_before_any_section() -> None:
    text = (
        "# renew_before_expiry = 30 days\n"
        "version = 5.8.0\n"
        "archive_dir = /etc/archive/a.test\n"
        "cert = /etc/live/a.test/cert.pem\n"
        "\n"
        "[renewalparams]\n"
        "server = https://acme.example/directory\n"
    )
    parsed = _parse_renewal_config(text)
    assert parsed[""]["version"] == "5.8.0"
    assert parsed[""]["archive_dir"] == "/etc/archive/a.test"
    assert parsed["renewalparams"]["server"] == "https://acme.example/directory"


def test_parser_ignores_comments_and_blank_lines() -> None:
    parsed = _parse_renewal_config("# c\n\n; other\n[renewalparams]\na = 1\n")
    assert parsed["renewalparams"] == {"a": "1"}


def test_parser_keeps_equals_signs_in_values() -> None:
    parsed = _parse_renewal_config("[renewalparams]\nserver = http://x/?a=b\n")
    assert parsed["renewalparams"]["server"] == "http://x/?a=b"


def test_parser_skips_lines_without_equals() -> None:
    parsed = _parse_renewal_config("[renewalparams]\nnot a pair\na = 1\n")
    assert parsed["renewalparams"] == {"a": "1"}


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


def test_save_lineage_creates_certbot_layout(store: CertStore, issued) -> None:
    lineage = store.save_lineage(
        issued=issued,
        private_key_pem="-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n",
        server="http://127.0.0.1:1/directory",
        account_id="acct1",
    )
    assert (lineage.archive_dir / "cert1.pem").exists()
    assert (lineage.archive_dir / "chain1.pem").exists()
    assert (lineage.archive_dir / "fullchain1.pem").exists()
    assert (lineage.archive_dir / "privkey1.pem").exists()
    assert lineage.live_dir.joinpath("README").exists()
    assert lineage.config_path.exists()
    assert lineage.version == 1


def test_live_entries_are_links_or_documented_copies(store: CertStore, issued) -> None:
    """Whatever the platform allows, the mode must be reported honestly."""
    lineage = store.save_lineage(
        issued=issued, private_key_pem="key", server="s", account_id="a"
    )
    assert lineage.link_mode in ("symlink", "copy")
    if lineage.link_mode == "symlink":
        assert lineage.cert_path.is_symlink()
    else:
        assert lineage.cert_path.is_file() and not lineage.cert_path.is_symlink()
    # In both modes the content must equal the archive version.
    assert lineage.cert_path.read_text(encoding="utf-8") == issued.cert_pem


def test_second_save_bumps_version(store: CertStore, issued) -> None:
    first = store.save_lineage(
        issued=issued, private_key_pem="k1", server="s", account_id="a"
    )
    second = store.save_lineage(
        issued=issued, private_key_pem="k2", server="s", account_id="a"
    )
    assert second.version == first.version + 1
    assert (second.archive_dir / "cert2.pem").exists()
    assert (second.archive_dir / "cert1.pem").exists(), "old versions must be retained"


def test_save_outside_root_is_refused(tmp_path: Path, issued) -> None:
    root = tmp_path / "etc"
    root.mkdir()
    store = CertStore(root, FilesystemGuard(root))
    # Two levels up from archive/ actually leaves the root; one level stays inside.
    with pytest.raises(PathEscape):
        store.save_lineage(
            issued=issued,
            private_key_pem="k",
            server="s",
            account_id="a",
            lineage_name="../../escape",
        )


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def test_list_lineages_reads_back_what_was_written(store: CertStore, issued) -> None:
    store.save_lineage(
        issued=issued, private_key_pem="k", server="http://srv/directory", account_id="a1"
    )
    lineages = store.list_lineages()
    assert len(lineages) == 1
    assert lineages[0].domain == "a.test"
    assert lineages[0].server == "http://srv/directory"
    assert lineages[0].account_id == "a1"
    assert lineages[0].domains == ["a.test"]


def test_get_returns_none_for_unknown_domain(store: CertStore) -> None:
    assert store.get("missing.test") is None


def test_days_remaining_reflects_certificate(store: CertStore, issued) -> None:
    lineage = store.save_lineage(
        issued=issued, private_key_pem="k", server="s", account_id="a"
    )
    days = store.days_remaining(lineage)
    assert days is not None
    assert 28 <= days <= 30


def test_parse_uses_top_level_cert_key(store: CertStore, issued) -> None:
    """The cert path lives at top level; reading only [renewalparams] loses it."""
    lineage = store.save_lineage(
        issued=issued, private_key_pem="k", server="s", account_id="a"
    )
    text = lineage.config_path.read_text(encoding="utf-8")
    assert "cert = " in text.split("[renewalparams]")[0]
    reparsed = store.get(lineage.domain)
    assert reparsed is not None
    assert reparsed.live_dir == lineage.live_dir


# --------------------------------------------------------------------------
# Deletion
# --------------------------------------------------------------------------


def test_delete_removes_live_archive_and_config(store: CertStore, issued) -> None:
    lineage = store.save_lineage(
        issued=issued, private_key_pem="k", server="s", account_id="a"
    )
    removed = store.delete_lineage(lineage.domain)
    assert removed
    assert not lineage.live_dir.exists()
    assert not lineage.archive_dir.exists()
    assert not lineage.config_path.exists()
    assert store.list_lineages() == []


def test_delete_of_unknown_lineage_removes_nothing(store: CertStore) -> None:
    assert store.delete_lineage("nope.test") == []
