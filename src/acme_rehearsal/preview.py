"""Read-only impact preview for destructive certbot operations.

The dangerous part of certificate operations is not the cryptography, it is the
blast radius: which lineages renew, which files get replaced, which hook fires
with which environment, and how much of a rate limit gets consumed. On a real
server you learn that by doing it.

This module answers the same questions by *reading* a config directory and
simulating the decision logic. It opens files for reading only — there is no
write path in this module at all, which is what makes it safe to point at a
production ``/etc/letsencrypt``.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509

from .store import CertStore, Lineage

__all__ = ["ImpactPreview", "OperationPreview", "Previewer", "PRODUCTION_SERVERS"]

#: Endpoints that spend real quota. Pointing a rehearsal at one of these is the
#: single most expensive mistake available, so the previewer calls it out.
PRODUCTION_SERVERS = (
    "https://acme-v02.api.letsencrypt.org/directory",
    "https://acme-v01.api.letsencrypt.org/directory",
)

#: Let's Encrypt production limits, as published. Used to frame the estimate;
#: the previewer never claims to know the account's actual current usage.
LE_CERTIFICATES_PER_DOMAIN_PER_WEEK = 50
LE_DUPLICATE_CERTIFICATES_PER_WEEK = 5

_EXPIRY_RE = re.compile(r"(\d+)\s*(day|days|hour|hours)", re.IGNORECASE)


@dataclass
class OperationPreview:
    """What one simulated operation would do."""

    operation: str
    risk: str
    would_affect: list[dict[str, Any]] = field(default_factory=list)
    would_skip: list[dict[str, Any]] = field(default_factory=list)
    files_touched: list[str] = field(default_factory=list)
    hook_environment: list[dict[str, str]] = field(default_factory=list)
    quota_estimate: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "risk": self.risk,
            "would_affect": list(self.would_affect),
            "would_skip": list(self.would_skip),
            "files_touched": list(self.files_touched),
            "hook_environment": list(self.hook_environment),
            "quota_estimate": dict(self.quota_estimate),
            "warnings": list(self.warnings),
            "summary": self.summary,
        }

    @property
    def summary(self) -> str:
        n = len(self.would_affect)
        if self.operation in ("renew", "renew-force"):
            return f"{n} lineage(s) would be renewed, {len(self.would_skip)} skipped"
        if self.operation == "revoke":
            return f"{n} certificate(s) would be revoked"
        if self.operation == "delete":
            return f"{n} lineage(s) would be deleted, {len(self.files_touched)} path(s) removed"
        return f"{n} item(s) affected"


@dataclass
class ImpactPreview:
    """The full read-only report for a config directory."""

    config_dir: str
    exists: bool
    lineages: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    operations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_dir": self.config_dir,
            "exists": self.exists,
            "lineage_count": len(self.lineages),
            "lineages": list(self.lineages),
            "warnings": list(self.warnings),
            "operations": dict(self.operations),
        }


class Previewer:
    """Simulate certbot decisions against a real config directory.

    The previewer only ever calls read-only store methods plus direct file reads.
    ``snapshot_proof`` lets a caller demonstrate that claim after the fact.
    """

    def __init__(self, config_dir: str | Path, *, now: _dt.datetime | None = None) -> None:
        self.config_dir = Path(config_dir)
        self._now = now or _dt.datetime.now(_dt.timezone.utc)
        # A guard with enforcement disabled: reads are allowed anywhere, and
        # because nothing here writes, the guard is never consulted for writes.
        from .guard import FilesystemGuard

        self._guard = FilesystemGuard(self.config_dir, enforce=False)
        self._store = CertStore(self.config_dir, self._guard)

    # -- scanning ----------------------------------------------------------

    def scan(self) -> ImpactPreview:
        exists = self.config_dir.exists()
        preview = ImpactPreview(config_dir=str(self.config_dir), exists=exists)
        if not exists:
            preview.warnings.append(
                f"config directory {self.config_dir} does not exist; nothing to preview"
            )
            return preview

        for lineage in self._store.list_lineages():
            preview.lineages.append(self._describe(lineage, preview.warnings))
        if not preview.lineages:
            preview.warnings.append(
                "no renewal configurations found; this directory is not a certbot config dir"
            )
        return preview

    def _describe(self, lineage: Lineage, warnings: list[str]) -> dict[str, Any]:
        info = lineage.to_dict()
        info["days_remaining"] = self._days_remaining(lineage)
        info["renew_before_expiry"] = self._renew_threshold(lineage)
        info["expired"] = (info["days_remaining"] or 0) <= 0
        info["cert_subject"] = self._subject(lineage)
        info["chain_length"] = self._chain_length(lineage)

        if lineage.server in PRODUCTION_SERVERS:
            warnings.append(
                f"{lineage.domain}: server points at the Let's Encrypt production "
                "endpoint; any real operation here spends production quota"
            )
        if lineage.link_mode != "symlink":
            warnings.append(
                f"{lineage.domain}: live/ entries are copies, not symlinks; a renewal "
                "would update archive/ but leave live/ stale"
            )
        if info["expired"]:
            warnings.append(f"{lineage.domain}: certificate is already expired")
        if info["chain_length"] == 0:
            # One intermediate is the normal shape (leaf is not in chain.pem).
            # Zero means the chain file is empty and TLS clients cannot build a
            # path to a trusted root.
            warnings.append(
                f"{lineage.domain}: chain.pem is empty; TLS clients will fail to "
                "build a path to a trusted root"
            )
        if self._is_manual_without_hook(lineage):
            warnings.append(
                f"{lineage.domain}: authenticator is manual without an auth hook; "
                "unattended renewal will fail"
            )
        return info

    def _days_remaining(self, lineage: Lineage) -> int | None:
        for candidate in (lineage.cert_path, self._latest_archive(lineage, "cert")):
            if candidate is None or not candidate.exists():
                continue
            try:
                cert = x509.load_pem_x509_certificate(candidate.read_bytes())
            except ValueError:
                continue
            delta = cert.not_valid_after_utc - self._now
            return max(0, delta.days)
        return None

    def _latest_archive(self, lineage: Lineage, kind: str) -> Path | None:
        matches = sorted(lineage.archive_dir.glob(f"{kind}*.pem"))
        return matches[-1] if matches else None

    def _subject(self, lineage: Lineage) -> str | None:
        path = self._latest_archive(lineage, "cert")
        if path is None:
            return None
        try:
            return x509.load_pem_x509_certificate(path.read_bytes()).subject.rfc4514_string()
        except ValueError:
            return None

    def _chain_length(self, lineage: Lineage) -> int:
        path = self._latest_archive(lineage, "chain")
        if path is None or not path.exists():
            return 0
        return path.read_text(encoding="utf-8", errors="replace").count(
            "-----BEGIN CERTIFICATE-----"
        )

    def _renew_threshold(self, lineage: Lineage) -> int:
        """Days before expiry at which certbot would renew (default: 30)."""
        text = lineage.config_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"#\s*renew_before_expiry\s*=\s*(.+)", text)
        if not match:
            return 30
        return _parse_days(match.group(1).strip(), default=30)

    def _is_manual_without_hook(self, lineage: Lineage) -> bool:
        text = lineage.config_path.read_text(encoding="utf-8", errors="replace")
        manual = re.search(r"^authenticator\s*=\s*manual", text, re.MULTILINE)
        hook = re.search(r"^(manual_auth_hook|pre_hook|deploy_hook)\s*=", text, re.MULTILINE)
        return bool(manual) and not hook

    # -- simulations -------------------------------------------------------

    def preview_renew(self, *, force: bool = False) -> OperationPreview:
        """Simulate ``certbot renew`` (or ``--force-renewal``)."""
        preview = OperationPreview(
            operation="renew-force" if force else "renew",
            risk="medium" if force else "low",
        )
        issued = 0
        for lineage in self._store.list_lineages():
            days = self._days_remaining(lineage)
            threshold = self._renew_threshold(lineage)
            due = force or days is None or days <= threshold
            entry = {
                "domain": lineage.domain,
                "days_remaining": days,
                "renew_before_expiry": threshold,
                "reason": (
                    "forced"
                    if force
                    else ("expiry unknown" if days is None else f"{days}d <= {threshold}d")
                    if due
                    else f"{days}d > {threshold}d"
                ),
            }
            if due:
                issued += 1
                preview.would_affect.append(entry)
                preview.files_touched.extend(
                    str(p) for p in self._files_a_renewal_would_write(lineage)
                )
                preview.hook_environment.append(
                    {
                        "RENEWED_LINEAGE": str(lineage.live_dir),
                        "RENEWED_DOMAINS": " ".join(lineage.domains),
                    }
                )
                if lineage.server in PRODUCTION_SERVERS:
                    preview.warnings.append(
                        f"{lineage.domain}: renewal would consume production quota"
                    )
            else:
                preview.would_skip.append(entry)

        preview.quota_estimate = {
            "certificates_requested": issued,
            "production_limit_per_domain_per_week": LE_CERTIFICATES_PER_DOMAIN_PER_WEEK,
            "note": (
                "Let's Encrypt counts each renewed certificate against the "
                "per-registered-domain weekly limit; five failures per hour per "
                "account also trigger a lockout."
            ),
        }
        if force and issued > 0:
            preview.warnings.append(
                "forced renewal reissues every lineage; doing this on a cron loop is "
                "the classic way to exhaust the weekly limit"
            )
        return preview

    def preview_revoke(self) -> OperationPreview:
        """Simulate revoking every lineage's current certificate."""
        preview = OperationPreview(operation="revoke", risk="high")
        for lineage in self._store.list_lineages():
            preview.would_affect.append(
                {
                    "domain": lineage.domain,
                    "domains": list(lineage.domains),
                    "live_dir": str(lineage.live_dir),
                    "impact": "any service serving this certificate fails TLS validation",
                }
            )
            preview.files_touched.append(str(lineage.cert_path))
        if preview.would_affect:
            preview.warnings.append(
                "revocation is not reversible; the only recovery is issuing a new "
                "certificate, which itself spends quota"
            )
        return preview

    def preview_delete(self) -> OperationPreview:
        """Simulate ``certbot delete`` for every lineage."""
        preview = OperationPreview(operation="delete", risk="high")
        for lineage in self._store.list_lineages():
            preview.would_affect.append(
                {"domain": lineage.domain, "live_dir": str(lineage.live_dir)}
            )
            for target in (lineage.live_dir, lineage.archive_dir):
                if target.exists():
                    preview.files_touched.extend(str(p) for p in sorted(target.rglob("*")))
                    preview.files_touched.append(str(target))
            preview.files_touched.append(str(lineage.config_path))
        if preview.would_affect:
            preview.warnings.append(
                "deleting a lineage also deletes its private key; if no backup exists "
                "the certificate cannot be reinstalled"
            )
        return preview

    def preview_expand(self, extra_domains: Iterable[str]) -> OperationPreview:
        """Simulate ``certbot --expand -d ...`` against the first lineage."""
        preview = OperationPreview(operation="expand", risk="medium")
        lineages = self._store.list_lineages()
        if not lineages:
            preview.warnings.append("no lineage to expand")
            return preview
        lineage = lineages[0]
        current = set(lineage.domains)
        additions = [d.lower() for d in extra_domains if d.lower() not in current]
        preview.would_affect.append(
            {
                "domain": lineage.domain,
                "current_domains": sorted(current),
                "added_domains": additions,
                "new_total": len(current) + len(additions),
            }
        )
        preview.quota_estimate = {
            "certificates_requested": 1 if additions else 0,
            "note": "expansion reissues the whole certificate with the larger SAN set",
        }
        if additions:
            preview.files_touched.extend(
                str(p) for p in self._files_a_renewal_would_write(lineage)
            )
        return preview

    def _files_a_renewal_would_write(self, lineage: Lineage) -> list[Path]:
        """The next archive version plus the live symlinks that point at it."""
        from .store import _LINK_NAMES  # noqa: PLC0415 - avoids a cycle at import time

        next_version = lineage.version + 1
        paths = [
            lineage.archive_dir / f"{name}{next_version}.pem" for name in _LINK_NAMES
        ]
        paths.extend(lineage.live_dir / f"{name}.pem" for name in _LINK_NAMES)
        paths.append(lineage.config_path)
        return paths


def _parse_days(text: str, *, default: int) -> int:
    match = _EXPIRY_RE.search(text)
    if not match:
        return default
    value = int(match.group(1))
    unit = match.group(2).lower()
    return max(0, value // 24) if unit.startswith("hour") else value
