"""Protocol-level tests.

The JWK thumbprint test uses the RFC 7638 section 3.1 worked example. That vector
is the only way to prove the canonicalisation is right: a subtly wrong member
order or a stray space still produces a stable-looking hash, just not the hash
every other ACME implementation computes.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acme_rehearsal.protocol import (
    AcmeProblem,
    NonceStore,
    b64u,
    b64u_decode,
    dns01_txt_value,
    jwk_from_public_key,
    jwk_thumbprint,
    key_authorization,
    public_key_from_jwk,
    sign_jws,
    verify_jws,
)

# RFC 7638 section 3.1
_RFC7638_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6"
        "tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-6"
        "5YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
        "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKn"
        "qDKgw"
    ),
    "e": "AQAB",
}
_RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


# --------------------------------------------------------------------------
# base64url
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"\xfb\xff", "-_8"),
    ],
)
def test_b64u_matches_rfc4648_vectors(raw: bytes, expected: str) -> None:
    assert b64u(raw) == expected
    assert b64u_decode(expected) == raw


def test_b64u_roundtrip_is_lossless_for_random_bytes() -> None:
    import os

    for length in (0, 1, 2, 3, 31, 32, 33, 255):
        payload = os.urandom(length)
        assert b64u_decode(b64u(payload)) == payload


def test_b64u_never_emits_padding() -> None:
    for length in range(0, 12):
        assert "=" not in b64u(b"\x00" * length)


def test_b64u_decode_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        b64u_decode("not base64 !!!")
    with pytest.raises(ValueError):
        b64u_decode(b"bytes-not-str")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# JWK
# --------------------------------------------------------------------------


def test_thumbprint_matches_rfc7638_worked_example() -> None:
    assert jwk_thumbprint(_RFC7638_JWK) == _RFC7638_THUMBPRINT


def test_thumbprint_is_independent_of_member_order_and_extras() -> None:
    """Canonicalisation must sort members and ignore anything not required."""
    shuffled = {"e": _RFC7638_JWK["e"], "n": _RFC7638_JWK["n"], "kty": "RSA"}
    with_extra = {**_RFC7638_JWK, "kid": "ignored", "use": "sig"}
    assert jwk_thumbprint(shuffled) == _RFC7638_THUMBPRINT
    assert jwk_thumbprint(with_extra) == _RFC7638_THUMBPRINT


def test_thumbprint_rejects_incomplete_jwk() -> None:
    with pytest.raises(ValueError):
        jwk_thumbprint({"kty": "RSA", "e": "AQAB"})


def test_rsa_jwk_roundtrip() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwk_from_public_key(key.public_key())
    assert jwk["kty"] == "RSA"
    rebuilt = public_key_from_jwk(jwk)
    assert rebuilt.public_numbers() == key.public_key().public_numbers()


def test_ec_jwk_roundtrip_and_fixed_width() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwk_from_public_key(key.public_key())
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    # P-256 coordinates are 32 bytes; a shorter integer must be zero-padded or
    # other implementations read a different key.
    assert len(b64u_decode(jwk["x"])) == 32
    assert len(b64u_decode(jwk["y"])) == 32
    assert public_key_from_jwk(jwk).public_numbers() == key.public_key().public_numbers()


def test_jwk_from_unsupported_curve_is_rejected() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError):
        jwk_from_public_key(key.public_key())


def test_public_key_from_jwk_reports_missing_member() -> None:
    with pytest.raises(ValueError, match="missing member"):
        public_key_from_jwk({"kty": "EC", "crv": "P-256", "x": "AA"})


# --------------------------------------------------------------------------
# JWS
# --------------------------------------------------------------------------


def test_jws_roundtrip_rs256() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jws = sign_jws(key, {"url": "http://127.0.0.1/new-order", "nonce": "n1"}, {"a": 1})
    header, payload = verify_jws(
        jws, key.public_key(), expected_url="http://127.0.0.1/new-order"
    )
    assert header["alg"] == "RS256"
    assert header["nonce"] == "n1"
    assert json.loads(payload) == {"a": 1}


def test_jws_roundtrip_es256() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://127.0.0.1/authz/z1"}, None)
    header, payload = verify_jws(
        jws, key.public_key(), expected_url="http://127.0.0.1/authz/z1"
    )
    assert header["alg"] == "ES256"
    assert payload == b""


def test_es256_signature_is_raw_concatenation_not_der() -> None:
    """JOSE requires r||s. A DER signature is variable length and would break peers."""
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://x/"}, {"a": 1})
    assert len(b64u_decode(jws["signature"])) == 64


def test_jws_rejects_tampered_payload() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://x/"}, {"amount": 1})
    jws["payload"] = b64u(json.dumps({"amount": 999}).encode())
    with pytest.raises(AcmeProblem) as exc:
        verify_jws(jws, key.public_key())
    assert exc.value.error_type == "unauthorized"


def test_jws_rejects_url_mismatch() -> None:
    """A JWS captured for one endpoint must not be replayable at another."""
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://127.0.0.1/new-order"}, {"a": 1})
    with pytest.raises(AcmeProblem) as exc:
        verify_jws(jws, key.public_key(), expected_url="http://127.0.0.1/revoke-cert")
    assert exc.value.error_type == "unauthorized"


def test_jws_rejects_alg_key_mismatch() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(rsa_key, {"url": "http://x/"}, {"a": 1})
    with pytest.raises(AcmeProblem) as exc:
        verify_jws(jws, ec_key.public_key())
    assert exc.value.error_type == "badSignatureAlgorithm"


def test_jws_rejects_unprotected_header() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://x/"}, {"a": 1})
    jws["header"] = {"kid": "smuggled"}
    with pytest.raises(AcmeProblem) as exc:
        verify_jws(jws, key.public_key())
    assert exc.value.error_type == "malformed"


def test_jws_rejects_missing_member() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jws = sign_jws(key, {"url": "http://x/"}, {"a": 1})
    del jws["signature"]
    with pytest.raises(AcmeProblem) as exc:
        verify_jws(jws, key.public_key())
    assert exc.value.error_type == "malformed"


# --------------------------------------------------------------------------
# key authorization / DNS-01
# --------------------------------------------------------------------------


def test_key_authorization_is_token_dot_thumbprint() -> None:
    assert key_authorization("tok", _RFC7638_JWK) == f"tok.{_RFC7638_THUMBPRINT}"


def test_dns01_value_is_base64url_sha256_of_key_authorization() -> None:
    import hashlib

    value = dns01_txt_value("tok.thumb")
    assert value == b64u(hashlib.sha256(b"tok.thumb").digest())
    assert "=" not in value


# --------------------------------------------------------------------------
# Nonces
# --------------------------------------------------------------------------


def test_nonce_is_single_use() -> None:
    store = NonceStore()
    nonce = store.issue()
    assert store.consume(nonce) is True
    assert store.consume(nonce) is False


def test_unknown_nonce_is_rejected() -> None:
    assert NonceStore().consume("never-issued") is False


def test_nonce_expires() -> None:
    now = [0.0]
    store = NonceStore(ttl_seconds=10, clock=lambda: now[0])
    nonce = store.issue()
    now[0] = 11.0
    assert store.consume(nonce) is False


def test_nonce_stats_track_rejections() -> None:
    store = NonceStore()
    store.issue()
    store.consume("bogus")
    stats = store.stats
    assert stats["issued"] == 1
    assert stats["rejected"] == 1
    assert stats["consumed"] == 0


def test_issued_nonces_are_unique() -> None:
    store = NonceStore()
    assert len({store.issue() for _ in range(200)}) == 200


# --------------------------------------------------------------------------
# Problems
# --------------------------------------------------------------------------


def test_problem_serialises_to_rfc7807_shape() -> None:
    problem = AcmeProblem("badNonce", "stale", status=400)
    body = problem.to_dict()
    assert body["type"] == "urn:ietf:params:acme:error:badNonce"
    assert body["detail"] == "stale"
    assert body["status"] == 400


def test_problem_carries_identifier_and_subproblems() -> None:
    problem = AcmeProblem(
        "badCSR",
        "nope",
        identifier={"type": "dns", "value": "a.test"},
        subproblems=[{"type": "urn:ietf:params:acme:error:unauthorized"}],
    )
    body = problem.to_dict()
    assert body["identifier"] == {"type": "dns", "value": "a.test"}
    assert len(body["subproblems"]) == 1


def test_unknown_error_type_is_a_programming_error() -> None:
    """Emitting an unregistered URN would be a protocol lie."""
    with pytest.raises(ValueError):
        AcmeProblem("madeUpType", "x")
