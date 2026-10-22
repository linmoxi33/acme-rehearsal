"""Local certificate authority for the rehearsal sandbox.

The sandbox needs certificates that are *real* X.509 objects: they must parse,
chain-verify and pass ``openssl verify``. Anything less and a rehearsal teaches
the wrong thing. So this module issues genuine certificates from a locally
generated root, and nothing it produces is ever trusted outside the sandbox
directory.

Trust boundary: the root CA is generated fresh per sandbox run and its private
key never leaves the sandbox directory. There is no code path here that can
contact a public CA.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = [
    "CA_KEY_FILE",
    "CA_CERT_FILE",
    "IntermediateFile",
    "IssuedCertificate",
    "LocalCA",
    "certificate_info",
    "verify_chain",
]

CA_KEY_FILE = "root-ca.key.pem"
CA_CERT_FILE = "root-ca.cert.pem"
INTERMEDIATE_KEY_FILE = "intermediate-ca.key.pem"
INTERMEDIATE_CERT_FILE = "intermediate-ca.cert.pem"

#: Let's Encrypt issues 90-day certificates; the sandbox defaults to the same so
#: that renewal-threshold rehearsals behave realistically. Tests override it.
DEFAULT_LEAF_VALIDITY_DAYS = 90


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _new_serial() -> int:
    """128-bit random serial.

    x509 requires a positive integer; masking the top bit guarantees that.
    """
    return secrets.randbits(127) | (1 << 126)


def _key_usage(*, is_ca: bool) -> x509.KeyUsage:
    if is_ca:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _basic_constraints(*, is_ca: bool, path_length: int | None = None) -> x509.BasicConstraints:
    return x509.BasicConstraints(ca=is_ca, path_length=path_length)


def _pem_private(key: Any) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _ski(public_key: Any) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(public_key)


@dataclass(frozen=True)
class IssuedCertificate:
    """A leaf certificate plus the chain material a TLS server would install."""

    cert_pem: str
    chain_pem: str
    fullchain_pem: str
    key_pem: str
    serial: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    sans: tuple[str, ...]

    @property
    def days_remaining(self) -> int:
        return max(0, (self.not_after - _utcnow()).days)


@dataclass
class IntermediateFile:
    key_pem: str
    cert_pem: str


class LocalCA:
    """A two-tier CA: offline root signs a single intermediate, which signs leaves.

    Two tiers rather than one is deliberate. Let's Encrypt serves a chain
    (leaf + intermediate), and a rehearsal that hands back a bare leaf would
    train users to deploy an incomplete chain. The intermediate exists so that
    ``chain.pem`` and ``fullchain.pem`` are genuinely different files.
    """

    def __init__(
        self,
        root_key: Any,
        root_cert: x509.Certificate,
        intermediate_key: Any,
        intermediate_cert: x509.Certificate,
        *,
        clock=_utcnow,
    ) -> None:
        self._root_key = root_key
        self._root_cert = root_cert
        self._intermediate_key = intermediate_key
        self._intermediate_cert = intermediate_cert
        self._clock = clock
        self._revoked: dict[str, dict[str, Any]] = {}

    # -- construction ------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        organization: str = "ACME Rehearsal Sandbox",
        root_common_name: str = "Rehearsal Sandbox Root CA",
        intermediate_common_name: str = "Rehearsal Sandbox Intermediate CA",
        validity_days: int = 3650,
        clock=_utcnow,
    ) -> LocalCA:
        now = clock()
        # EC P-256 keeps sandbox startup fast; leaves are still RSA by default so
        # they look like what certbot actually issues.
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, root_common_name),
            ]
        )
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(_new_serial())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=validity_days))
            .add_extension(_basic_constraints(is_ca=True, path_length=1), critical=True)
            .add_extension(_key_usage(is_ca=True), critical=True)
            .add_extension(_ski(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256())
        )

        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, intermediate_common_name),
            ]
        )
        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(intermediate_name)
            .issuer_name(root_cert.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(_new_serial())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=validity_days))
            .add_extension(_basic_constraints(is_ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(is_ca=True), critical=True)
            .add_extension(_ski(intermediate_key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        return cls(root_key, root_cert, intermediate_key, intermediate_cert, clock=clock)

    # -- accessors ---------------------------------------------------------

    @property
    def root_cert_pem(self) -> str:
        return _pem_cert(self._root_cert)

    @property
    def intermediate_cert_pem(self) -> str:
        return _pem_cert(self._intermediate_cert)

    @property
    def chain_pem(self) -> str:
        """The chain a server sends after its leaf: just the intermediate."""
        return self.intermediate_cert_pem

    @property
    def revoked_serials(self) -> tuple[str, ...]:
        return tuple(self._revoked)

    # -- issuance ----------------------------------------------------------

    def issue(
        self,
        public_key: Any,
        sans: Sequence[str],
        *,
        validity_days: int = DEFAULT_LEAF_VALIDITY_DAYS,
        private_key_pem: str | None = None,
    ) -> IssuedCertificate:
        """Sign a leaf certificate for ``sans``.

        The caller supplies the key pair; the CA never generates or stores leaf
        private keys on the server side, mirroring how ACME works (the client
        sends a CSR and keeps the key).
        """
        clean = [s.strip().lower() for s in sans if s and s.strip()]
        if not clean:
            raise ValueError("at least one SAN is required")
        if len(set(clean)) != len(clean):
            raise ValueError("duplicate SANs are not allowed")

        now = self._clock()
        not_before = now - _dt.timedelta(minutes=5)
        not_after = now + _dt.timedelta(days=validity_days)

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, clean[0])]))
            .issuer_name(self._intermediate_cert.subject)
            .public_key(public_key)
            .serial_number(_new_serial())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(_basic_constraints(is_ca=False), critical=True)
            .add_extension(_key_usage(is_ca=False), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in clean]),
                critical=False,
            )
            .add_extension(_ski(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._intermediate_key.public_key()
                ),
                critical=False,
            )
        )
        cert = builder.sign(self._intermediate_key, hashes.SHA256())
        cert_pem = _pem_cert(cert)
        chain_pem = self.chain_pem

        return IssuedCertificate(
            cert_pem=cert_pem,
            chain_pem=chain_pem,
            fullchain_pem=cert_pem + chain_pem,
            key_pem=private_key_pem or "",
            serial=format(cert.serial_number, "x"),
            not_before=not_before,
            not_after=not_after,
            sans=tuple(clean),
        )

    def issue_from_csr(
        self,
        csr_pem: str,
        *,
        validity_days: int = DEFAULT_LEAF_VALIDITY_DAYS,
    ) -> IssuedCertificate:
        """Sign a CSR, preserving the subject public key exactly as submitted."""
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n) for n in san_ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound as exc:
            raise ValueError("CSR has no subjectAltName extension") from exc
        return self.issue(csr.public_key(), sans, validity_days=validity_days)

    # -- revocation --------------------------------------------------------

    def revoke(self, serial: str, *, reason: str = "unspecified") -> None:
        serial = serial.lower().lstrip("0") or "0"
        if serial in self._revoked:
            raise ValueError(f"certificate {serial} is already revoked")
        self._revoked[serial] = {
            "serial": serial,
            "reason": reason,
            "revoked_at": self._clock().isoformat(),
        }

    def is_revoked(self, serial: str) -> bool:
        return (serial.lower().lstrip("0") or "0") in self._revoked

    def crl_pem(self, *, valid_days: int = 7) -> str:
        """Build a CRL listing every revoked serial.

        A CRL that does not parse is worse than none, so this always goes through
        the real builder rather than emitting placeholder bytes.
        """
        now = self._clock()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._intermediate_cert.subject)
            .last_update(now - _dt.timedelta(minutes=5))
            .next_update(now + _dt.timedelta(days=valid_days))
        )
        for entry in self._revoked.values():
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(entry["serial"], 16))
                .revocation_date(_dt.datetime.fromisoformat(entry["revoked_at"]))
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        crl = builder.sign(self._intermediate_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # -- persistence -------------------------------------------------------

    def save(self, directory: os.PathLike[str] | str) -> Path:
        """Persist CA material. Files are written 0600 where the OS honours it."""
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        for name, content in (
            (CA_KEY_FILE, _pem_private(self._root_key)),
            (CA_CERT_FILE, self.root_cert_pem),
            (INTERMEDIATE_KEY_FILE, _pem_private(self._intermediate_key)),
            (INTERMEDIATE_CERT_FILE, self.intermediate_cert_pem),
        ):
            _write_secret(target / name, content)
        (target / "revoked.json").write_text(
            json.dumps(list(self._revoked.values()), indent=2) + "\n", encoding="utf-8"
        )
        return target

    @classmethod
    def load(cls, directory: os.PathLike[str] | str, *, clock=_utcnow) -> LocalCA:
        source = Path(directory)
        root_key = serialization.load_pem_private_key(
            (source / CA_KEY_FILE).read_bytes(), password=None
        )
        root_cert = x509.load_pem_x509_certificate((source / CA_CERT_FILE).read_bytes())
        int_key = serialization.load_pem_private_key(
            (source / INTERMEDIATE_KEY_FILE).read_bytes(), password=None
        )
        int_cert = x509.load_pem_x509_certificate(
            (source / INTERMEDIATE_CERT_FILE).read_bytes()
        )
        instance = cls(root_key, root_cert, int_key, int_cert, clock=clock)
        revoked_file = source / "revoked.json"
        if revoked_file.exists():
            for entry in json.loads(revoked_file.read_text(encoding="utf-8")):
                instance._revoked[entry["serial"]] = entry
        return instance


def _write_secret(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    if os.name == "posix":
        os.chmod(path, 0o600)


# --------------------------------------------------------------------------
# Verification helpers
# --------------------------------------------------------------------------


def certificate_info(pem: str) -> dict[str, Any]:
    """Summarise a certificate for transcripts and reports."""
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    try:
        sans = [str(n.value) for n in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value]
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "sans": sans,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }


def _signature_ok(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify that ``issuer`` signed ``cert``.

    Uses the same key-family dispatch the CA does, so an EC-signed leaf and an
    RSA-signed leaf both verify.
    """
    public_key = issuer.public_key()
    data = cert.tbs_certificate_bytes
    sig = cert.signature
    hash_alg = cert.signature_hash_algorithm
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(sig, data, ec.ECDSA(hash_alg))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(sig, data, padding.PKCS1v15(), hash_alg)
        else:
            return False
    except Exception:
        return False
    return True


def verify_chain(
    leaf_pem: str,
    intermediates: Iterable[str],
    root_pem: str,
) -> list[str]:
    """Walk a chain leaf -> intermediates -> root.

    Returns the list of subjects visited. Raises ValueError on the first broken
    link, naming it precisely: a rehearsal whose chain silently "verifies" is
    worse than one that fails loudly.
    """
    chain = [x509.load_pem_x509_certificate(p.encode("ascii")) for p in intermediates]
    root = x509.load_pem_x509_certificate(root_pem.encode("ascii"))
    current = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    visited = [current.subject.rfc4514_string()]

    for candidate in chain:
        if current.issuer != candidate.subject:
            raise ValueError(
                f"chain broken: {current.subject.rfc4514_string()} was not issued by "
                f"{candidate.subject.rfc4514_string()}"
            )
        if not _signature_ok(current, candidate):
            raise ValueError(
                f"bad signature: {candidate.subject.rfc4514_string()} did not sign "
                f"{current.subject.rfc4514_string()}"
            )
        visited.append(candidate.subject.rfc4514_string())
        current = candidate

    if current.issuer != root.subject:
        raise ValueError(
            f"chain does not terminate at root: last issuer "
            f"{current.issuer.rfc4514_string()} != {root.subject.rfc4514_string()}"
        )
    if not _signature_ok(current, root):
        raise ValueError(f"bad signature: root did not sign {current.subject.rfc4514_string()}")
    visited.append(root.subject.rfc4514_string())
    return visited
