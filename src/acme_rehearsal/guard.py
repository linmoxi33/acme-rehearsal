"""Containment primitives: egress blocking and write-scope enforcement.

The whole value of a rehearsal is the guarantee that nothing leaked. Two
guarantees are enforced mechanically rather than promised in prose:

1. **No egress.** Every name resolution and every outbound ``connect`` is
   inspected. Loopback is permitted (the sandbox talks to itself over real TCP);
   anything else raises :class:`EgressBlocked`. Public CA hostnames are denied
   *before* resolution, so a poisoned hosts file cannot smuggle a request out.

2. **No writes outside the sandbox.** :class:`FilesystemGuard` refuses any path
   that resolves outside the sandbox root, and records every permitted write.

Both are context managers so that the guarded window is explicit in code and in
the transcript.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import threading
import traceback
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "PUBLIC_CA_HOSTS",
    "EgressBlocked",
    "EgressGuard",
    "FilesystemGuard",
    "PathEscape",
    "directory_snapshot",
    "diff_snapshots",
]

#: Hostnames that must never be reached, even if they resolve to loopback.
#: Denying them pre-resolution is what makes the guarantee DNS-independent.
PUBLIC_CA_HOSTS = frozenset(
    {
        "acme-v01.api.letsencrypt.org",
        "acme-v02.api.letsencrypt.org",
        "acme-staging.api.letsencrypt.org",
        "acme-staging-v02.api.letsencrypt.org",
        "acme.zerossl.com",
        "acme-v02.api.buypass.com",
        "acme.api.buypass.com",
    }
)


class EgressBlocked(RuntimeError):
    """Raised when sandboxed code attempts to reach a non-loopback endpoint."""

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(f"egress blocked: {target} ({reason})")
        self.target = target
        self.reason = reason


class PathEscape(RuntimeError):
    """Raised when sandboxed code attempts to write outside the sandbox root."""

    def __init__(self, path: str, root: str) -> None:
        super().__init__(f"write outside sandbox root: {path} (root={root})")
        self.path = path
        self.root = root


@dataclass
class EgressAttempt:
    kind: str  # "resolve" | "connect"
    target: str
    allowed: bool
    reason: str = ""
    caller: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "kind": self.kind,
            "target": self.target,
            "allowed": self.allowed,
            "reason": self.reason,
        }
        if self.caller:
            payload["caller"] = self.caller
        return payload


def _caller_frame(skip: int = 2) -> str:
    """Best-effort caller description, excluding this module's own frames."""
    stack = traceback.extract_stack()
    for frame in reversed(stack[:-skip]):
        if "acme_rehearsal/guard.py" in frame.filename.replace("\\", "/"):
            continue
        return f"{Path(frame.filename).name}:{frame.lineno} in {frame.name}"
    return ""


def _is_loopback_host(host: str) -> bool:
    if not host:
        return False
    if host.lower() in {"localhost", "localhost.localdomain", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_loopback_sockaddr(sockaddr: Any) -> bool:
    if not isinstance(sockaddr, tuple) or not sockaddr:
        return False
    return _is_loopback_host(str(sockaddr[0]))


#: Process-wide installation flag. Nesting two guards (even different instances)
#: would make the inner one capture the outer one's patched functions as
#: "originals", so restoring would leave the socket layer patched forever.
_INSTALL_LOCK = threading.Lock()
_INSTALLED = False


class EgressGuard:
    """Patch the socket layer for the duration of a sandbox run.

    Patching is process-wide while active. That is intentional: a subprocess
    spawned mid-rehearsal would otherwise escape the guard, so the sandbox never
    spawns network-capable subprocesses and this guard covers the parent.
    """

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str] = (),
        deny_hosts: Iterable[str] = PUBLIC_CA_HOSTS,
        allow_loopback: bool = True,
    ) -> None:
        self._allowed_extra = {h.lower() for h in allowed_hosts}
        self._denied = {h.lower() for h in deny_hosts}
        self._allow_loopback = allow_loopback
        self._attempts: list[EgressAttempt] = []
        self._lock = threading.Lock()
        self._active = False
        self._originals: dict[str, Any] = {}

    # -- public API --------------------------------------------------------

    @property
    def attempts(self) -> list[EgressAttempt]:
        with self._lock:
            return list(self._attempts)

    @property
    def blocked(self) -> list[EgressAttempt]:
        return [a for a in self.attempts if not a.allowed]

    def report(self) -> dict[str, Any]:
        attempts = self.attempts
        return {
            "active": self._active,
            "total_attempts": len(attempts),
            "blocked_count": sum(1 for a in attempts if not a.allowed),
            "outbound_connections": sum(
                1 for a in attempts if a.kind == "connect" and a.allowed
            ),
            "denied_hosts": sorted(self._denied),
            "attempts": [a.to_dict() for a in attempts],
            "verdict": "no-egress" if not self.blocked else "egress-attempted",
        }

    def __enter__(self) -> EgressGuard:
        self._install()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self._restore()

    # -- internals ---------------------------------------------------------

    def _record(self, attempt: EgressAttempt) -> None:
        with self._lock:
            self._attempts.append(attempt)

    def _check_host(self, host: str, kind: str) -> EgressAttempt:
        lowered = host.lower()
        if lowered in self._denied:
            attempt = EgressAttempt(
                kind, host, False, "public CA hostname denied pre-resolution",
                _caller_frame(3),
            )
            self._record(attempt)
            return attempt
        if _is_loopback_host(host) and self._allow_loopback:
            attempt = EgressAttempt(kind, host, True, "loopback", _caller_frame(3))
            self._record(attempt)
            return attempt
        if lowered in self._allowed_extra:
            attempt = EgressAttempt(kind, host, True, "explicitly allowed", _caller_frame(3))
            self._record(attempt)
            return attempt
        attempt = EgressAttempt(kind, host, False, "non-loopback destination", _caller_frame(3))
        self._record(attempt)
        return attempt

    def _install(self) -> None:
        global _INSTALLED
        with _INSTALL_LOCK:
            if _INSTALLED:
                raise RuntimeError(
                    "an EgressGuard is already active in this process; "
                    "nesting would corrupt socket restoration"
                )
            _INSTALLED = True
        self._active = True

        self._originals["getaddrinfo"] = socket.getaddrinfo
        self._originals["connect"] = socket.socket.connect
        self._originals["connect_ex"] = socket.socket.connect_ex
        self._originals["create_connection"] = socket.create_connection

        guard = self

        def guarded_getaddrinfo(host, port, *args, **kwargs):
            host_str = host.decode() if isinstance(host, bytes) else str(host)
            attempt = guard._check_host(host_str, "resolve")
            if not attempt.allowed:
                raise EgressBlocked(f"{host_str}:{port}", attempt.reason)
            return guard._originals["getaddrinfo"](host, port, *args, **kwargs)

        def guarded_connect(sock_self, address):
            if sock_self.family in (socket.AF_INET, socket.AF_INET6):
                host = str(address[0]) if isinstance(address, tuple) else str(address)
                attempt = guard._check_host(host, "connect")
                if not attempt.allowed:
                    raise EgressBlocked(host, attempt.reason)
            return guard._originals["connect"](sock_self, address)

        def guarded_connect_ex(sock_self, address):
            if sock_self.family in (socket.AF_INET, socket.AF_INET6):
                host = str(address[0]) if isinstance(address, tuple) else str(address)
                attempt = guard._check_host(host, "connect")
                if not attempt.allowed:
                    raise EgressBlocked(host, attempt.reason)
            return guard._originals["connect_ex"](sock_self, address)

        def guarded_create_connection(address, *args, **kwargs):
            host = str(address[0]) if isinstance(address, tuple) else str(address)
            attempt = guard._check_host(host, "connect")
            if not attempt.allowed:
                raise EgressBlocked(host, attempt.reason)
            return guard._originals["create_connection"](address, *args, **kwargs)

        socket.getaddrinfo = guarded_getaddrinfo
        socket.socket.connect = guarded_connect
        socket.socket.connect_ex = guarded_connect_ex
        socket.create_connection = guarded_create_connection

    def _restore(self) -> None:
        global _INSTALLED
        if not self._active:
            return
        socket.getaddrinfo = self._originals["getaddrinfo"]
        socket.socket.connect = self._originals["connect"]
        socket.socket.connect_ex = self._originals["connect_ex"]
        socket.create_connection = self._originals["create_connection"]
        self._active = False
        with _INSTALL_LOCK:
            _INSTALLED = False


class FilesystemGuard:
    """Restrict all sandbox writes to a single root directory.

    Reads are unrestricted (the impact preview must read a real certbot config
    directory); writes are not.
    """

    def __init__(self, root: os.PathLike[str] | str, *, enforce: bool = True) -> None:
        self.root = Path(root).resolve()
        self.enforce = enforce
        self._writes: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def writes(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._writes)

    def report(self) -> dict[str, Any]:
        writes = self.writes
        return {
            "root": str(self.root),
            "enforced": self.enforce,
            "write_count": len(writes),
            "total_bytes": sum(int(w.get("bytes", 0)) for w in writes),
            "writes": writes,
        }

    def check(self, path: os.PathLike[str] | str) -> Path:
        """Resolve ``path`` and assert it lives under the sandbox root."""
        candidate = Path(path)
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = Path(os.path.abspath(candidate))
        if self.enforce and not _is_within(resolved, self.root):
            raise PathEscape(str(resolved), str(self.root))
        return resolved

    def record_write(self, path: os.PathLike[str] | str, size: int, kind: str = "write") -> None:
        resolved = self.check(path)
        with self._lock:
            self._writes.append(
                {"path": str(resolved), "bytes": size, "kind": kind}
            )

    def write_text(
        self, path: os.PathLike[str] | str, content: str, *, newline: str = "\n"
    ) -> Path:
        target = self.check(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline=newline)
        self.record_write(target, len(content.encode("utf-8")))
        return target

    def write_bytes(self, path: os.PathLike[str] | str, content: bytes) -> Path:
        target = self.check(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        self.record_write(target, len(content))
        return target


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


def directory_snapshot(
    directory: os.PathLike[str] | str,
    *,
    max_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Hash every regular file under ``directory``.

    Used to prove the rehearsal did not touch a real certbot config directory:
    take a snapshot before, take one after, demand byte equality.

    Symlinks are recorded by target rather than followed, because certbot's
    ``live/`` tree is symlink-heavy and following would double-count.
    """
    root = Path(directory)
    entries: dict[str, dict[str, Any]] = {}
    if not root.exists():
        return {"root": str(root), "exists": False, "entries": {}}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            try:
                if full.is_symlink():
                    entries[rel] = {"type": "symlink", "target": os.readlink(full)}
                    continue
                stat = full.stat()
                if stat.st_size > max_bytes:
                    entries[rel] = {
                        "type": "file",
                        "size": stat.st_size,
                        "sha256": None,
                        "note": "exceeds hash limit",
                    }
                    continue
                digest = hashlib.sha256(full.read_bytes()).hexdigest()
                entries[rel] = {
                    "type": "file",
                    "size": stat.st_size,
                    "sha256": digest,
                    "mode": oct(stat.st_mode & 0o777),
                }
            except OSError as exc:
                entries[rel] = {"type": "error", "error": str(exc)}

    return {"root": str(root.resolve()), "exists": True, "entries": entries}


def diff_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two snapshots and classify every difference.

    ``identical`` is only True when the entry maps are equal; any added, removed
    or changed file makes the rehearsal fail its no-side-effect assertion.
    """
    b = dict(before.get("entries", {}))
    a = dict(after.get("entries", {}))
    added = sorted(set(a) - set(b))
    removed = sorted(set(b) - set(a))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return {
        "identical": not (added or removed or changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "file_count": len(b),
    }
