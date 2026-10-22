"""certbot-compatible lineage storage.

The sandbox writes certificates into the same on-disk layout certbot uses, so a
rehearsal produces artifacts a learner can inspect with the same commands they
would use on a real server:

    <config>/live/<domain>/cert.pem          -> symlink into archive/
    <config>/archive/<domain>/cert1.pem
    <config>/renewal/<domain>.conf           INI consumed by `certbot renew`

One platform difference is handled explicitly rather than papered over: creating
symlinks on Windows requires either Developer Mode or an elevated process. When
that fails, the store falls back to copying the archive file into ``live/`` and
records ``link_mode="copy"``. The fallback is *reported*, never silent, because a
copied ``live/`` tree behaves differently on renewal — certbot replaces symlink
targets, while a copy would go stale.
"""

from __future__ import annotations

import configparser
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ca import IssuedCertificate
from .guard import FilesystemGuard

__all__ = ["CertStore", "Lineage", "LIVE_README"]

LIVE_README = """\
This directory contains your keys and certificates.

`privkey.pem`  : the private key for your certificate.
`fullchain.pem`: the certificate file used in most server software.
`chain.pem`    : used for OCSP stapling in Nginx >=1.3.7.
`cert.pem`     : will break many server configurations, and should not be used
                 without reading further documentation (see link below).

We recommend not moving these files. For more information, see the Certbot
User Guide at https://certbot.eff.org/docs/using.html#where-are-my-certificates.
"""

_LINK_NAMES = ("cert", "chain", "fullchain", "privkey")


@dataclass
class Lineage:
    """One managed certificate: its paths, provenance and link strategy."""

    domain: str
    live_dir: Path
    archive_dir: Path
    config_path: Path
    server: str
    account_id: str
    domains: list[str]
    version: int
    link_mode: str
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def cert_path(self) -> Path:
        return self.live_dir / "cert.pem"

    @property
    def fullchain_path(self) -> Path:
        return self.live_dir / "fullchain.pem"

    @property
    def privkey_path(self) -> Path:
        return self.live_dir / "privkey.pem"

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "live_dir": str(self.live_dir),
            "archive_dir": str(self.archive_dir),
            "config_path": str(self.config_path),
            "server": self.server,
            "account_id": self.account_id,
            "domains": list(self.domains),
            "version": self.version,
            "link_mode": self.link_mode,
            **({"extra": dict(self.extra)} if self.extra else {}),
        }


class CertStore:
    """Reads and writes a certbot-shaped config directory.

    All writes go through the :class:`FilesystemGuard`, so a rehearsal cannot
    touch a path outside the sandbox root even if a caller passes an absolute
    path by mistake.
    """

    def __init__(self, root: os.PathLike[str] | str, guard: FilesystemGuard) -> None:
        self.root = Path(root).resolve()
        self.guard = guard
        self.live = self.root / "live"
        self.archive = self.root / "archive"
        self.renewal = self.root / "renewal"
        self.accounts = self.root / "accounts"

    # -- writing -----------------------------------------------------------

    def save_lineage(
        self,
        *,
        issued: IssuedCertificate,
        private_key_pem: str,
        server: str,
        account_id: str,
        authenticator: str = "standalone",
        key_type: str = "rsa",
        renew_before_expiry: str = "30 days",
        lineage_name: str | None = None,
    ) -> Lineage:
        """Persist a certificate as a new archive version and refresh ``live/``."""
        name = (lineage_name or issued.sans[0]).lower()
        archive_dir = self.archive / name
        live_dir = self.live / name
        self.guard.check(archive_dir)
        self.guard.check(live_dir)
        archive_dir.mkdir(parents=True, exist_ok=True)
        live_dir.mkdir(parents=True, exist_ok=True)
        self.renewal.mkdir(parents=True, exist_ok=True)

        version = self._next_version(archive_dir)
        files = {
            "cert": issued.cert_pem,
            "chain": issued.chain_pem,
            "fullchain": issued.fullchain_pem,
            "privkey": private_key_pem,
        }
        archive_paths: dict[str, Path] = {}
        for key, content in files.items():
            target = archive_dir / f"{key}{version}.pem"
            self.guard.write_text(target, content)
            archive_paths[key] = target

        link_mode = self._materialise_links(live_dir, archive_paths)
        readme = live_dir / "README"
        if not readme.exists():
            self.guard.write_text(readme, LIVE_README)

        config_path = self.renewal / f"{name}.conf"
        self.guard.write_text(
            config_path,
            _render_renewal_config(
                domain=name,
                version=version,
                archive_dir=archive_dir,
                live_dir=live_dir,
                server=server,
                account_id=account_id,
                authenticator=authenticator,
                key_type=key_type,
                renew_before_expiry=renew_before_expiry,
            ),
        )
        self.guard.write_text(
            self.accounts / "sandbox-account.json",
            _account_record(account_id=account_id, server=server),
        )

        return Lineage(
            domain=name,
            live_dir=live_dir,
            archive_dir=archive_dir,
            config_path=config_path,
            server=server,
            account_id=account_id,
            domains=list(issued.sans),
            version=version,
            link_mode=link_mode,
        )

    def _next_version(self, archive_dir: Path) -> int:
        existing = [
            int(p.stem.replace("cert", ""))
            for p in archive_dir.glob("cert*.pem")
            if p.stem.replace("cert", "").isdigit()
        ]
        return max(existing, default=0) + 1

    def _materialise_links(self, live_dir: Path, archive_paths: dict[str, Path]) -> str:
        """Create ``live/*.pem`` links, falling back to copies.

        Returns the mode actually used for the whole set: ``symlink`` only if
        every link was created as a symlink.
        """
        mode = "symlink"
        for key, archive_path in archive_paths.items():
            link_path = live_dir / f"{key}.pem"
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()
            relative = os.path.relpath(archive_path, live_dir)
            try:
                os.symlink(relative, link_path)
            except (OSError, NotImplementedError, AttributeError):
                shutil.copyfile(archive_path, link_path)
                mode = "copy"
        return mode

    # -- reading -----------------------------------------------------------

    def list_lineages(self) -> list[Lineage]:
        """Parse ``renewal/*.conf`` the way ``certbot certificates`` would."""
        if not self.renewal.exists():
            return []
        lineages: list[Lineage] = []
        for config_path in sorted(self.renewal.glob("*.conf")):
            try:
                lineages.append(self._parse_lineage(config_path))
            except (configparser.Error, KeyError, ValueError):
                continue
        return lineages

    def get(self, domain: str) -> Lineage | None:
        target = (self.renewal / f"{domain.lower()}.conf")
        if not target.exists():
            return None
        return self._parse_lineage(target)

    def _parse_lineage(self, config_path: Path) -> Lineage:
        text = config_path.read_text(encoding="utf-8", errors="replace")
        data = _parse_renewal_config(text)
        params = data.get("renewalparams", {})
        top = data.get("", {})
        cert_value = params.get("cert") or top.get("cert") or ""
        live_dir = Path(cert_value).parent if cert_value else self.live / config_path.stem
        archive_value = top.get("archive_dir") or ""
        archive_dir = Path(archive_value) if archive_value else self.archive / config_path.stem
        version = self._next_version(archive_dir) - 1
        link_mode = "symlink" if (live_dir / "cert.pem").is_symlink() else "copy"
        domains = [
            d.strip()
            for d in params.get("domains", config_path.stem).split(",")
            if d.strip()
        ]
        return Lineage(
            domain=config_path.stem,
            live_dir=live_dir,
            archive_dir=archive_dir,
            config_path=config_path,
            server=params.get("server", ""),
            account_id=params.get("account", ""),
            domains=domains or [config_path.stem],
            version=max(version, 1),
            link_mode=link_mode,
        )

    def days_remaining(self, lineage: Lineage) -> int | None:
        """Read the leaf's expiry without trusting the renewal config."""
        from cryptography import x509

        path = lineage.cert_path
        if not path.exists():
            return None
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
        except ValueError:
            return None
        import datetime as _dt

        delta = cert.not_valid_after_utc - _dt.datetime.now(_dt.timezone.utc)
        return max(0, delta.days)

    # -- destructive operations (sandbox-scoped) ---------------------------

    def delete_lineage(self, domain: str) -> list[str]:
        """Remove a lineage, returning the paths that were deleted.

        Only ever operates inside the sandbox root; the guard raises otherwise.
        """
        name = domain.lower()
        removed: list[str] = []
        for target in (self.live / name, self.archive / name):
            self.guard.check(target)
            if target.exists():
                for path in sorted(target.rglob("*")):
                    removed.append(str(path))
                shutil.rmtree(target)
                removed.append(str(target))
        config = self.renewal / f"{name}.conf"
        self.guard.check(config)
        if config.exists():
            config.unlink()
            removed.append(str(config))
        return removed


def _parse_renewal_config(text: str) -> dict[str, dict[str, str]]:
    """Parse certbot's renewal file format.

    certbot writes top-level keys (``version``, ``archive_dir``, ``cert``, ...)
    *before* any section header, which ``configparser`` rejects outright. certbot
    itself uses configobj, so a purpose-built parser here matches real files and
    avoids adding a dependency for one format.
    """
    sections: dict[str, dict[str, str]] = {"": {}}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        sections[current][key.strip()] = value.strip()
    return sections


def _render_renewal_config(
    *,
    domain: str,
    version: int,
    archive_dir: Path,
    live_dir: Path,
    server: str,
    account_id: str,
    authenticator: str,
    key_type: str,
    renew_before_expiry: str,
) -> str:
    """Render a renewal config in certbot's own format.

    Written by hand rather than through configparser so the leading comment and
    key order match what certbot produces; tooling that diffs these files would
    otherwise see spurious churn.
    """
    return (
        f"# renew_before_expiry = {renew_before_expiry}\n"
        f"version = 5.8.0\n"
        f"archive_dir = {archive_dir}\n"
        f"cert = {live_dir / 'cert.pem'}\n"
        f"privkey = {live_dir / 'privkey.pem'}\n"
        f"chain = {live_dir / 'chain.pem'}\n"
        f"fullchain = {live_dir / 'fullchain.pem'}\n"
        f"\n"
        f"# Options used in the renewal process\n"
        f"[renewalparams]\n"
        f"account = {account_id}\n"
        f"authenticator = {authenticator}\n"
        f"server = {server}\n"
        f"key_type = {key_type}\n"
        f"domains = {domain}\n"
    )


def _account_record(*, account_id: str, server: str) -> str:
    import json

    return json.dumps(
        {"account_id": account_id, "server": server, "sandbox": True},
        indent=2,
        sort_keys=True,
    ) + "\n"
