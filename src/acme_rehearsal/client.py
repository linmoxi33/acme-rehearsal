"""ACME client used by the rehearsal.

Deliberately dependency-light: ``http.client`` plus ``cryptography``. The client
is not meant to replace certbot in production — it exists so the sandbox can
drive a complete issuance without importing a second ACME stack that might drift
from the server's assumptions.

It does implement the behaviours that matter pedagogically:

* nonce handling, including the ``badNonce`` retry that every real client needs;
* ``POST-as-GET`` for reads;
* CSR construction with SANs only (no CN), matching modern CA expectations;
* problem-document parsing that surfaces the ACME error URN rather than an
  opaque HTTP status.
"""

from __future__ import annotations

import http.client
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .protocol import AcmeProblem, b64u, jwk_from_public_key, sign_jws

__all__ = ["AcmeClient", "IssuanceResult", "build_csr", "generate_account_key", "generate_leaf_key"]


def generate_account_key(*, key_type: str = "ec") -> Any:
    """Account keys default to EC P-256: fast, and ES256 is widely supported."""
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f"unknown key type {key_type!r}")


def generate_leaf_key(*, key_type: str = "rsa", key_size: int = 2048) -> Any:
    """Leaf keys default to RSA 2048, which is what certbot issues by default."""
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    raise ValueError(f"unknown key type {key_type!r}")


def _private_key_pem(key: Any) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def build_csr(domains: list[str], private_key: Any) -> bytes:
    """Build a DER-encoded CSR carrying every domain as a SAN.

    No subject CN is set: it has been deprecated for hostname validation since
    RFC 6125 and some CAs reject CSRs whose CN disagrees with the SAN set.
    """
    clean = [d.strip().lower() for d in domains if d and d.strip()]
    if not clean:
        raise ValueError("at least one domain is required")
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in clean]),
            critical=False,
        )
    )
    return builder.sign(private_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


@dataclass
class IssuanceResult:
    """Everything a deployment needs, plus the provenance of the issuance."""

    domains: list[str]
    cert_pem: str
    chain_pem: str
    fullchain_pem: str
    private_key_pem: str
    order_url: str
    account_url: str
    challenge_type: str
    elapsed_ms: float
    steps: list[dict[str, Any]] = field(default_factory=list)


class AcmeClient:
    """Synchronous ACME client bound to a single directory URL."""

    def __init__(
        self,
        directory_url: str,
        account_key: Any,
        *,
        contact: list[str] | None = None,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parsed = urlparse(directory_url)
        if parsed.scheme != "http":
            # The sandbox is loopback-only and deliberately plaintext: adding TLS
            # would mean shipping a trust store, which is out of scope and would
            # obscure the ACME mechanics being taught.
            raise ValueError("sandbox directory URL must use http://")
        self._scheme = parsed.scheme
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or 80
        self._directory_url = directory_url
        self._key = account_key
        self._jwk = jwk_from_public_key(account_key.public_key())
        self._contact = list(contact or [])
        self._timeout = timeout
        self._clock = clock
        self._nonce: str | None = None
        self._kid: str | None = None
        self._directory: dict[str, Any] | None = None
        self.steps: list[dict[str, Any]] = []
        self._retry_count = 0

    # -- observability -----------------------------------------------------

    @property
    def account_url(self) -> str | None:
        return self._kid

    @property
    def bad_nonce_retries(self) -> int:
        return self._retry_count

    def _step(self, name: str, **detail: Any) -> None:
        self.steps.append({"step": name, "at_ms": round(self._clock() * 1000, 3), **detail})

    # -- transport ---------------------------------------------------------

    def _connect(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection = self._connect()
        try:
            connection.request(method, path, body=body, headers=dict(headers or {}))
            response = connection.getresponse()
            data = response.read()
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            nonce = response_headers.get("replay-nonce")
            if nonce:
                self._nonce = nonce
            return response.status, response_headers, data
        finally:
            connection.close()

    def _post(
        self, url: str, payload: Any, *, use_jwk: bool = False
    ) -> tuple[int, bytes, dict[str, str]]:
        """Signed POST with one badNonce retry, mirroring real client behaviour."""
        attempt = 0
        while True:
            if self._nonce is None:
                self._refresh_nonce()
            protected: dict[str, Any] = {
                "alg": "ES256" if isinstance(self._key, ec.EllipticCurvePrivateKey) else "RS256",
                "nonce": self._nonce,
                "url": url,
            }
            if use_jwk:
                protected["jwk"] = self._jwk
            else:
                if self._kid is None:
                    raise RuntimeError("account is not registered; call register() first")
                protected["kid"] = self._kid
            jws = sign_jws(self._key, protected, payload)
            status, headers, data = self._request(
                "POST",
                url,
                body=json.dumps(jws).encode("utf-8"),
                headers={"Content-Type": "application/jose+json"},
            )
            if status >= 400:
                problem = _parse_problem(status, data)
                if problem.error_type == "badNonce" and attempt == 0:
                    # A fresh nonce arrived in the error response's Replay-Nonce
                    # header, so re-signing once is sufficient.
                    attempt += 1
                    self._retry_count += 1
                    continue
                raise problem
            return status, data, headers

    def _refresh_nonce(self) -> None:
        status, headers, _ = self._request("HEAD", self._directory["newNonce"])
        if status >= 400 or "replay-nonce" not in headers:
            raise AcmeProblem("serverInternal", "could not obtain a nonce")

    # -- operations --------------------------------------------------------

    def fetch_directory(self) -> dict[str, Any]:
        status, _headers, data = self._request("GET", self._directory_url)
        if status != 200:
            raise AcmeProblem("serverInternal", f"directory returned {status}")
        directory = json.loads(data)
        required = {"newNonce", "newAccount", "newOrder"}
        missing = required - set(directory)
        if missing:
            raise AcmeProblem("serverInternal", f"directory missing {sorted(missing)}")
        self._directory = directory
        self._step("directory", url=self._directory_url, endpoints=sorted(directory))
        return directory

    def register(self, *, terms_of_service_agreed: bool = True) -> str:
        if self._directory is None:
            self.fetch_directory()
        payload: dict[str, Any] = {"termsOfServiceAgreed": terms_of_service_agreed}
        if self._contact:
            payload["contact"] = self._contact
        status, data, headers = self._post(
            self._directory["newAccount"], payload, use_jwk=True  # type: ignore[index]
        )
        location = headers.get("location")
        if not location:
            raise AcmeProblem("serverInternal", "new-account response lacked Location")
        self._kid = location
        self._step("account", status=status, account_url=location)
        return location

    def new_order(self, domains: list[str]) -> dict[str, Any]:
        if self._directory is None:
            self.fetch_directory()
        payload = {"identifiers": [{"type": "dns", "value": d.lower()} for d in domains]}
        status, data, headers = self._post(self._directory["newOrder"], payload)  # type: ignore[index]
        order = json.loads(data)
        order["_url"] = headers.get("location")
        self._step(
            "order",
            status=status,
            order_url=order["_url"],
            identifiers=[d.lower() for d in domains],
        )
        return order

    def fetch(self, url: str) -> dict[str, Any]:
        """POST-as-GET: empty payload, still signed."""
        _status, data, _headers = self._post(url, None)
        return json.loads(data)

    def fetch_raw(self, url: str) -> bytes:
        _status, data, _headers = self._post(url, None)
        return data

    def respond_challenge(self, url: str) -> dict[str, Any]:
        _status, data, _headers = self._post(url, {})
        return json.loads(data)

    def finalize(self, url: str, csr_der: bytes) -> dict[str, Any]:
        _status, data, _headers = self._post(url, {"csr": b64u(csr_der)})
        return json.loads(data)

    def revoke(self, cert_der: bytes, reason: int | None = None) -> None:
        if self._directory is None:
            self.fetch_directory()
        payload: dict[str, Any] = {"certificate": b64u(cert_der)}
        if reason is not None:
            payload["reason"] = reason
        self._post(self._directory["revokeCert"], payload)  # type: ignore[index]
        self._step("revoke", reason=reason)


def _parse_problem(status: int, data: bytes) -> AcmeProblem:
    try:
        body = json.loads(data)
    except json.JSONDecodeError:
        return AcmeProblem("serverInternal", f"HTTP {status} with non-JSON body", status=status)
    urn = str(body.get("type", ""))
    prefix = "urn:ietf:params:acme:error:"
    error_type = urn[len(prefix):] if urn.startswith(prefix) else "serverInternal"
    detail = str(body.get("detail", f"HTTP {status}"))
    try:
        return AcmeProblem(
            error_type,
            detail,
            status=int(body.get("status", status)),
            identifier=body.get("identifier"),
            subproblems=body.get("subproblems"),
        )
    except ValueError:
        return AcmeProblem("serverInternal", detail, status=status)


def chain_parts(fullchain_pem: str) -> tuple[str, str]:
    """Split a PEM chain into (leaf, rest).

    Used when storing what the server returned so that ``cert.pem`` and
    ``chain.pem`` are derived from one download rather than two requests.
    """
    blocks = _split_pem(fullchain_pem)
    if not blocks:
        raise ValueError("empty certificate chain")
    return blocks[0], "".join(blocks[1:])


def _split_pem(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines(keepends=True):
        current.append(line)
        if "-----END CERTIFICATE-----" in line:
            blocks.append("".join(current))
            current = []
    return blocks


def certificate_der(pem: str) -> bytes:
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    return cert.public_bytes(serialization.Encoding.DER)
