"""RFC 8555 protocol primitives.

This module contains the wire-level pieces of ACME that both the sandbox server
and the sandbox client share: base64url codecs, JWK/JWS handling, problem
documents and the one-shot nonce store.

Nothing here performs I/O. That separation matters: the sandbox can be tested
without opening a socket, and the server can be reasoned about independently of
its HTTP transport.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

__all__ = [
    "ACME_ERROR_URN",
    "AcmeProblem",
    "NonceStore",
    "b64u",
    "b64u_decode",
    "jwk_from_public_key",
    "jwk_thumbprint",
    "public_key_from_jwk",
    "sign_jws",
    "verify_jws",
]

ACME_ERROR_URN = "urn:ietf:params:acme:error:"

#: Error types defined by RFC 8555 section 6.7. Only the subset the sandbox can
#: actually emit is listed; emitting an unknown type would be a protocol lie.
ERROR_TYPES = frozenset(
    {
        "accountDoesNotExist",
        "alreadyRevoked",
        "badCSR",
        "badNonce",
        "badPublicKey",
        "badRevocationReason",
        "badSignatureAlgorithm",
        "compound",
        "externalAccountRequired",
        "incorrectResponse",
        "invalidContact",
        "malformed",
        "orderNotReady",
        "rateLimited",
        "rejectedIdentifier",
        "serverInternal",
        "unauthorized",
        "unsupportedContact",
        "unsupportedIdentifier",
        "userActionRequired",
    }
)


# --------------------------------------------------------------------------
# base64url
# --------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Decode unpadded base64url.

    Raises ValueError rather than binascii.Error so callers only need to catch
    one exception type when validating untrusted input.
    """
    if not isinstance(text, str):
        raise ValueError("base64url input must be str")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from exc


def _canonical_json_bytes(payload: Any) -> bytes:
    """Canonical JSON (no whitespace, sorted keys) as UTF-8 bytes.

    RFC 7638 requires the thumbprint input to use lexicographic key order with no
    whitespace, which is exactly what sort_keys + compact separators gives.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------
# JWK
# --------------------------------------------------------------------------


def _int_to_bytes(value: int, length: int | None = None) -> bytes:
    if length is None:
        length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def jwk_from_public_key(public_key: Any) -> dict[str, str]:
    """Render a public key as a JWK.

    Only the two algorithms ACME mandates are supported (RS256, ES256). Anything
    else raises ValueError instead of silently producing a key the peer cannot
    verify.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        return {
            "e": b64u(_int_to_bytes(numbers.e)),
            "kty": "RSA",
            "n": b64u(_int_to_bytes(numbers.n)),
        }
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError(f"unsupported EC curve: {public_key.curve.name}")
        numbers = public_key.public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64u(_int_to_bytes(numbers.x, 32)),
            "y": b64u(_int_to_bytes(numbers.y, 32)),
        }
    raise ValueError(f"unsupported key type: {type(public_key).__name__}")


def public_key_from_jwk(jwk: Mapping[str, Any]) -> Any:
    """Rebuild a cryptography public key from a JWK.

    Validates shape eagerly: a malformed JWK from an untrusted client must become
    a clean ValueError, not an IndexError deep inside the verifier.
    """
    if not isinstance(jwk, Mapping):
        raise ValueError("JWK must be an object")
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            n = int.from_bytes(b64u_decode(jwk["n"]), "big")
            e = int.from_bytes(b64u_decode(jwk["e"]), "big")
            if n <= 0 or e <= 0:
                raise ValueError("RSA parameters must be positive")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            if jwk.get("crv") != "P-256":
                raise ValueError(f"unsupported curve {jwk.get('crv')!r}")
            x = int.from_bytes(b64u_decode(jwk["x"]), "big")
            y = int.from_bytes(b64u_decode(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except KeyError as exc:
        raise ValueError(f"JWK missing member {exc.args[0]!r}") from exc
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid JWK: {exc}") from exc
    raise ValueError(f"unsupported JWK key type {kty!r}")


#: RFC 7638 section 3.2: required members per key type, in lexicographic order.
_THUMBPRINT_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
}


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Compute the RFC 7638 JWK thumbprint (base64url SHA-256).

    This is what binds an ACME account key to its account URL, so getting the
    member set or ordering wrong would silently produce a different key
    identifier than every other ACME implementation.
    """
    kty = jwk.get("kty")
    members = _THUMBPRINT_MEMBERS.get(kty)
    if members is None:
        raise ValueError(f"cannot compute thumbprint for key type {kty!r}")
    missing = [m for m in members if m not in jwk]
    if missing:
        raise ValueError(f"JWK missing members for thumbprint: {missing}")
    canonical = {m: jwk[m] for m in members}
    # The digest input is the canonical JSON *itself*; base64url is applied only
    # to the digest. Encoding the JSON first produces a stable but wrong
    # thumbprint that no other ACME implementation would agree with.
    return b64u(hashlib.sha256(_canonical_json_bytes(canonical)).digest())


def key_authorization(token: str, jwk: Mapping[str, Any]) -> str:
    """HTTP-01 key authorization: token || '.' || thumbprint."""
    return f"{token}.{jwk_thumbprint(jwk)}"


def dns01_txt_value(key_authorization_value: str) -> str:
    """DNS-01 record value: base64url(SHA-256(keyAuthorization))."""
    return b64u(hashlib.sha256(key_authorization_value.encode("ascii")).digest())


# --------------------------------------------------------------------------
# JWS
# --------------------------------------------------------------------------

#: alg name -> (hash algorithm, key family)
_SUPPORTED_ALGS = {
    "RS256": (hashes.SHA256, "RSA"),
    "ES256": (hashes.SHA256, "EC"),
}


def _alg_for_key(private_key: Any) -> str:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError(f"unsupported EC curve: {private_key.curve.name}")
        return "ES256"
    raise ValueError(f"unsupported private key: {type(private_key).__name__}")


def _sign_bytes(private_key: Any, alg: str, signing_input: bytes) -> bytes:
    hash_alg, _ = _SUPPORTED_ALGS[alg]
    if alg == "RS256":
        return private_key.sign(signing_input, padding.PKCS1v15(), hash_alg())
    # JOSE requires the raw r||s concatenation, not the DER encoding that
    # cryptography emits by default.
    der = private_key.sign(signing_input, ec.ECDSA(hash_alg()))
    r, s = decode_dss_signature(der)
    return _int_to_bytes(r, 32) + _int_to_bytes(s, 32)


def sign_jws(
    private_key: Any,
    protected: Mapping[str, Any],
    payload: bytes | Mapping[str, Any] | None,
) -> dict[str, str]:
    """Produce a flattened JWS JSON object.

    ``payload`` may be bytes, a JSON-serialisable mapping, or None. None encodes
    the empty payload used by POST-as-GET requests, which is distinct from the
    JSON string "".
    """
    header = dict(protected)
    header.setdefault("alg", _alg_for_key(private_key))
    if header["alg"] not in _SUPPORTED_ALGS:
        raise ValueError(f"unsupported JWS alg {header['alg']!r}")

    protected_b64 = b64u(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

    if payload is None:
        payload_b64 = ""
    elif isinstance(payload, (bytes, bytearray)):
        payload_b64 = b64u(bytes(payload))
    else:
        payload_b64 = b64u(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = _sign_bytes(private_key, header["alg"], signing_input)
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64u(signature),
    }


def verify_jws(
    jws: Mapping[str, Any],
    public_key: Any,
    *,
    expected_url: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Verify a flattened JWS and return (protected header, payload bytes).

    Raises AcmeProblem('malformed') or AcmeProblem('unauthorized') so the caller
    can turn a verification failure directly into an RFC 7807 response.
    """
    if not isinstance(jws, Mapping):
        raise AcmeProblem("malformed", "JWS body must be a JSON object")
    try:
        protected_b64 = jws["protected"]
        payload_b64 = jws["payload"]
        signature_b64 = jws["signature"]
    except KeyError as exc:
        raise AcmeProblem("malformed", f"JWS missing member {exc.args[0]!r}") from exc

    if not all(isinstance(v, str) for v in (protected_b64, payload_b64, signature_b64)):
        raise AcmeProblem("malformed", "JWS members must be strings")
    if jws.get("header") not in (None, {}):
        # RFC 8555 section 6.2 forbids the unprotected header.
        raise AcmeProblem("malformed", "unprotected JWS header is not allowed")

    try:
        header = json.loads(b64u_decode(protected_b64))
        payload = b64u_decode(payload_b64) if payload_b64 else b""
        signature = b64u_decode(signature_b64)
    except ValueError as exc:
        raise AcmeProblem("malformed", f"invalid JWS encoding: {exc}") from exc

    if not isinstance(header, dict):
        raise AcmeProblem("malformed", "protected header must be a JSON object")

    alg = header.get("alg")
    if alg not in _SUPPORTED_ALGS:
        raise AcmeProblem("badSignatureAlgorithm", f"unsupported alg {alg!r}")
    expected_family = _SUPPORTED_ALGS[alg][1]
    actual_family = "RSA" if isinstance(public_key, rsa.RSAPublicKey) else "EC"
    if expected_family != actual_family:
        raise AcmeProblem(
            "badSignatureAlgorithm",
            f"alg {alg} does not match key family {actual_family}",
        )

    if expected_url is not None and header.get("url") != expected_url:
        # Binding the URL prevents an attacker from replaying a JWS captured for
        # one endpoint against another.
        raise AcmeProblem(
            "unauthorized",
            f"JWS url {header.get('url')!r} does not match request URL {expected_url!r}",
        )

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    hash_alg = _SUPPORTED_ALGS[alg][0]
    try:
        if alg == "RS256":
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg())
        else:
            if len(signature) != 64:
                raise AcmeProblem("malformed", "ES256 signature must be 64 bytes")
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            public_key.verify(der, signing_input, ec.ECDSA(hash_alg()))
    except InvalidSignature as exc:
        raise AcmeProblem("unauthorized", "JWS signature verification failed") from exc

    return header, payload


# --------------------------------------------------------------------------
# Problems
# --------------------------------------------------------------------------


class AcmeProblem(Exception):
    """An RFC 7807 problem document with an ACME error type.

    Carrying the HTTP status on the exception keeps the server layer free of
    per-error mapping tables.
    """

    def __init__(
        self,
        error_type: str,
        detail: str,
        *,
        status: int = 400,
        identifier: Mapping[str, Any] | None = None,
        subproblems: list[Mapping[str, Any]] | None = None,
    ) -> None:
        if error_type not in ERROR_TYPES:
            raise ValueError(f"unknown ACME error type {error_type!r}")
        super().__init__(f"{error_type}: {detail}")
        self.error_type = error_type
        self.detail = detail
        self.status = status
        self.identifier = dict(identifier) if identifier else None
        self.subproblems = list(subproblems) if subproblems else []

    @property
    def urn(self) -> str:
        return ACME_ERROR_URN + self.error_type

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"type": self.urn, "detail": self.detail, "status": self.status}
        if self.identifier is not None:
            body["identifier"] = self.identifier
        if self.subproblems:
            body["subproblems"] = self.subproblems
        return body

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.error_type}: {self.detail}"


# --------------------------------------------------------------------------
# Nonces
# --------------------------------------------------------------------------


class NonceStore:
    """One-shot nonce issuance with TTL eviction.

    ACME nonces must be single-use; replaying one is a badNonce error. The store
    is thread-safe because the sandbox server handles each request on its own
    thread.
    """

    def __init__(self, ttl_seconds: float = 600.0, clock=time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._issued: dict[str, float] = {}
        self._issued_count = 0
        self._consumed_count = 0
        self._rejected_count = 0

    def issue(self) -> str:
        nonce = b64u(secrets.token_bytes(16))
        now = self._clock()
        with self._lock:
            self._evict(now)
            self._issued[nonce] = now + self._ttl
            self._issued_count += 1
        return nonce

    def consume(self, nonce: str) -> bool:
        """Consume a nonce. Returns False if unknown, already used, or expired."""
        now = self._clock()
        with self._lock:
            self._evict(now)
            if nonce in self._issued:
                del self._issued[nonce]
                self._consumed_count += 1
                return True
            self._rejected_count += 1
            return False

    def _evict(self, now: float) -> None:
        expired = [n for n, deadline in self._issued.items() if deadline <= now]
        for nonce in expired:
            del self._issued[nonce]

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "issued": self._issued_count,
                "consumed": self._consumed_count,
                "rejected": self._rejected_count,
                "outstanding": len(self._issued),
            }


def constant_time_equals(a: str, b: str) -> bool:
    """Compare two strings without leaking length or content via timing."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
