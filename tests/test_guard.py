"""Containment tests.

These are the tests that make the product's central claim checkable: a rehearsal
cannot reach the network and cannot write outside its root. Each assertion targets
an observable side effect — a raised exception, an attempt log entry, a changed
file hash — rather than the presence of a code path.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from acme_rehearsal.guard import (
    PUBLIC_CA_HOSTS,
    EgressBlocked,
    EgressGuard,
    FilesystemGuard,
    PathEscape,
    diff_snapshots,
    directory_snapshot,
)

# --------------------------------------------------------------------------
# Egress
# --------------------------------------------------------------------------


def test_guard_blocks_dns_resolution_of_external_host() -> None:
    """Resolution must fail *before* any packet leaves: the guard is pre-DNS."""
    with EgressGuard() as guard:
        with pytest.raises(EgressBlocked):
            socket.getaddrinfo("example.com", 80)
        blocked = guard.blocked
    assert len(blocked) == 1
    assert blocked[0].kind == "resolve"
    assert blocked[0].target == "example.com"
    assert "non-loopback" in blocked[0].reason


def test_guard_denies_public_ca_hosts_before_resolution() -> None:
    """A poisoned hosts file must not turn a CA hostname into a loopback call."""
    for host in sorted(PUBLIC_CA_HOSTS):
        with EgressGuard() as guard:
            with pytest.raises(EgressBlocked):
                socket.getaddrinfo(host, 443)
            attempts = guard.blocked
        assert len(attempts) == 1, host
        assert "public CA" in attempts[0].reason, host


def test_guard_denies_public_ca_hostnames_even_as_literal_connect_target() -> None:
    """Denial happens on the hostname, so a rewritten /etc/hosts cannot bypass it."""
    with EgressGuard() as guard:
        with pytest.raises(EgressBlocked):
            socket.create_connection(("acme-v02.api.letsencrypt.org", 443), timeout=1)
        assert guard.blocked[0].reason.startswith("public CA")


def test_guard_blocks_connect_to_external_ip_literal() -> None:
    """IP literals skip DNS, so connect itself has to be guarded too."""
    with EgressGuard() as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(EgressBlocked):
                sock.connect(("93.184.216.34", 80))
        finally:
            sock.close()
        blocked = guard.blocked
    assert len(blocked) == 1
    assert blocked[0].kind == "connect"
    assert blocked[0].target == "93.184.216.34"


def test_guard_allows_loopback() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        with EgressGuard() as guard:
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.close()
            accepted, _ = server.accept()
            accepted.close()
            report = guard.report()
    finally:
        server.close()

    assert report["blocked_count"] == 0
    assert report["outbound_connections"] >= 1
    assert report["verdict"] == "no-egress"
    assert all(a["allowed"] for a in report["attempts"])


def test_guard_allows_localhost_name() -> None:
    with EgressGuard() as guard:
        socket.getaddrinfo("localhost", 80)
        report = guard.report()
    assert report["blocked_count"] == 0
    assert any(a["target"] == "localhost" and a["allowed"] for a in report["attempts"])


def test_guard_restores_socket_layer_on_exit() -> None:
    original = socket.getaddrinfo
    with EgressGuard():
        assert socket.getaddrinfo is not original
    assert socket.getaddrinfo is original


def test_guard_restores_even_when_body_raises() -> None:
    original = socket.create_connection
    with pytest.raises(RuntimeError), EgressGuard():
        raise RuntimeError("boom")
    assert socket.create_connection is original


def test_guard_is_not_reentrant() -> None:
    """Nested installs would restore the patched function, not the original."""
    with EgressGuard(), pytest.raises(RuntimeError), EgressGuard():
        pass


def test_guard_report_counts_attempts_by_kind() -> None:
    with EgressGuard() as guard:
        with pytest.raises(EgressBlocked):
            socket.getaddrinfo("evil.test", 80)
        with pytest.raises(EgressBlocked):
            socket.create_connection(("1.2.3.4", 80), timeout=1)
        report = guard.report()
    assert report["total_attempts"] == 2
    assert report["blocked_count"] == 2
    assert report["verdict"] == "egress-attempted"


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------


def test_write_inside_root_is_allowed_and_recorded(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    guard = FilesystemGuard(root)
    target = guard.write_text(root / "a" / "b.txt", "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    report = guard.report()
    assert report["write_count"] == 1
    assert report["total_bytes"] == 5
    assert Path(report["writes"][0]["path"]).is_relative_to(root.resolve())


def test_write_outside_root_raises_and_writes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    guard = FilesystemGuard(root)
    with pytest.raises(PathEscape):
        guard.write_text(outside, "should not exist")
    assert not outside.exists(), "guard must refuse before touching the filesystem"


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    guard = FilesystemGuard(root)
    with pytest.raises(PathEscape):
        guard.write_text(root / ".." / "escaped.txt", "x")
    assert not (tmp_path / "escaped.txt").exists()


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    """A symlink inside the root pointing outside must not be a write path.

    This is the interesting case: a naive prefix check on the *unresolved* path
    would pass, because the string starts with the root.
    """
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    guard = FilesystemGuard(root)
    with pytest.raises(PathEscape):
        guard.write_text(link / "evil.txt", "x")
    assert not (outside / "evil.txt").exists()


def test_enforce_false_permits_external_paths(tmp_path: Path) -> None:
    """The previewer needs read access anywhere; enforcement is opt-out, not opt-in."""
    guard = FilesystemGuard(tmp_path, enforce=False)
    assert guard.check(tmp_path / "anywhere.txt")


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


def test_snapshot_of_identical_tree_is_identical(tmp_path: Path) -> None:
    root = tmp_path / "cfg"
    root.mkdir()
    (root / "a.txt").write_text("one", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_text("two", encoding="utf-8")

    before = directory_snapshot(root)
    after = directory_snapshot(root)
    diff = diff_snapshots(before, after)
    assert diff["identical"] is True
    assert diff["file_count"] == 2


def test_snapshot_detects_modification(tmp_path: Path) -> None:
    root = tmp_path / "cfg"
    root.mkdir()
    (root / "a.txt").write_text("one", encoding="utf-8")
    before = directory_snapshot(root)
    (root / "a.txt").write_text("two", encoding="utf-8")
    after = directory_snapshot(root)
    diff = diff_snapshots(before, after)
    assert diff["identical"] is False
    assert diff["changed"] == ["a.txt"]


def test_snapshot_detects_addition_and_removal(tmp_path: Path) -> None:
    root = tmp_path / "cfg"
    root.mkdir()
    (root / "keep.txt").write_text("k", encoding="utf-8")
    (root / "gone.txt").write_text("g", encoding="utf-8")
    before = directory_snapshot(root)
    (root / "gone.txt").unlink()
    (root / "new.txt").write_text("n", encoding="utf-8")
    after = directory_snapshot(root)
    diff = diff_snapshots(before, after)
    assert diff["added"] == ["new.txt"]
    assert diff["removed"] == ["gone.txt"]
    assert diff["identical"] is False


def test_snapshot_records_symlink_target_without_following(tmp_path: Path) -> None:
    root = tmp_path / "cfg"
    root.mkdir()
    (root / "real.txt").write_text("r", encoding="utf-8")
    try:
        os.symlink("real.txt", root / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    snapshot = directory_snapshot(root)
    assert snapshot["entries"]["link.txt"]["type"] == "symlink"
    assert snapshot["entries"]["link.txt"]["target"] == "real.txt"


def test_snapshot_of_missing_directory_is_marked_absent(tmp_path: Path) -> None:
    snapshot = directory_snapshot(tmp_path / "nope")
    assert snapshot["exists"] is False
    assert snapshot["entries"] == {}


def test_snapshot_is_stable_across_repeated_calls(tmp_path: Path) -> None:
    """Hashes must not depend on walk order or mtime."""
    root = tmp_path / "cfg"
    root.mkdir()
    for name in ("z.txt", "a.txt", "m.txt"):
        (root / name).write_text(name, encoding="utf-8")
    first = json.dumps(directory_snapshot(root)["entries"], sort_keys=True)
    second = json.dumps(directory_snapshot(root)["entries"], sort_keys=True)
    assert first == second
