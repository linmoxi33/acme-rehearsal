"""CA tests.

The chain tests deliberately tamper with material: a verifier that only ever sees
valid input proves nothing.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acme_rehearsal.ca import (
    CA_CERT_FILE,
    CA_KEY_FILE,
    INTERMEDIATE_CERT_FILE,
    LocalCA,
    certificate_info,
    verify_chain,
)


@pytest.fixture
def ca() -> LocalCA:
    return LocalCA.create()


@pytest.fixture
def leaf_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_issued_certificate_carries_all_sans(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test", "b.test"], validity_days=30)
    info = certificate_info(issued.cert_pem)
    assert info["sans"] == ["a.test", "b.test"]


def test_issued_certificate_chain_verifies(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    visited = verify_chain(issued.cert_pem, [issued.chain_pem], ca.root_cert_pem)
    assert len(visited) == 3
    assert "Root CA" in visited[-1]


def test_chain_has_two_distinct_files(ca: LocalCA, leaf_key) -> None:
    """chain.pem must be the intermediate, not a copy of the leaf."""
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    assert issued.chain_pem != issued.cert_pem
    assert "BEGIN CERTIFICATE" in issued.chain_pem
    assert issued.fullchain_pem == issued.cert_pem + issued.chain_pem


def test_leaf_is_not_a_ca(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is False


def test_leaf_has_server_auth_eku(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_validity_window_matches_request(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"], validity_days=7)
    span = issued.not_after - issued.not_before
    # not_before is backdated 5 minutes, so the span is slightly over 7 days.
    assert _dt.timedelta(days=7) <= span <= _dt.timedelta(days=7, minutes=10)


def test_serial_numbers_are_unique(ca: LocalCA, leaf_key) -> None:
    serials = {
        ca.issue(leaf_key.public_key(), [f"h{i}.test"]).serial for i in range(5)
    }
    assert len(serials) == 5


def test_duplicate_sans_rejected(ca: LocalCA, leaf_key) -> None:
    with pytest.raises(ValueError, match="duplicate"):
        ca.issue(leaf_key.public_key(), ["a.test", "a.test"])


def test_empty_sans_rejected(ca: LocalCA, leaf_key) -> None:
    with pytest.raises(ValueError, match="at least one"):
        ca.issue(leaf_key.public_key(), [])


def test_ec_leaf_also_verifies(ca: LocalCA) -> None:
    """The verifier dispatches on key family; an EC leaf must not be special-cased out."""
    key = ec.generate_private_key(ec.SECP256R1())
    issued = ca.issue(key.public_key(), ["ec.test"])
    assert len(verify_chain(issued.cert_pem, [issued.chain_pem], ca.root_cert_pem)) == 3


# --------------------------------------------------------------------------
# Negative chain verification
# --------------------------------------------------------------------------


def test_chain_fails_when_leaf_is_swapped(ca: LocalCA, leaf_key) -> None:
    first = ca.issue(leaf_key.public_key(), ["a.test"])
    other_ca = LocalCA.create()
    other = other_ca.issue(leaf_key.public_key(), ["a.test"])
    with pytest.raises(ValueError):
        verify_chain(other.cert_pem, [first.chain_pem], ca.root_cert_pem)


def test_chain_fails_when_root_is_wrong(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    other = LocalCA.create()
    with pytest.raises(ValueError):
        verify_chain(issued.cert_pem, [issued.chain_pem], other.root_cert_pem)


def test_chain_fails_when_intermediate_is_missing(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    with pytest.raises(ValueError):
        verify_chain(issued.cert_pem, [], ca.root_cert_pem)


def test_chain_fails_on_bitflip_in_signature(ca: LocalCA, leaf_key) -> None:
    """Corrupt the DER body while keeping PEM structure valid."""
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    der[-5] ^= 0xFF
    tampered = x509.load_der_x509_certificate(bytes(der))
    tampered_pem = tampered.public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(ValueError, match="bad signature"):
        verify_chain(tampered_pem, [issued.chain_pem], ca.root_cert_pem)


# --------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------


def test_revocation_is_recorded(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    ca.revoke(issued.serial, reason="superseded")
    assert ca.is_revoked(issued.serial)
    assert issued.serial in ca.revoked_serials


def test_double_revocation_is_an_error(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    ca.revoke(issued.serial)
    with pytest.raises(ValueError, match="already revoked"):
        ca.revoke(issued.serial)


def test_revocation_normalises_leading_zeros(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    ca.revoke(f"0000{issued.serial}")
    assert ca.is_revoked(issued.serial)


def test_crl_parses_and_lists_revoked_serials(ca: LocalCA, leaf_key) -> None:
    first = ca.issue(leaf_key.public_key(), ["a.test"])
    second = ca.issue(leaf_key.public_key(), ["b.test"])
    ca.revoke(first.serial, reason="keyCompromise")
    ca.revoke(second.serial, reason="superseded")

    crl = x509.load_pem_x509_crl(ca.crl_pem().encode())
    serials = {format(entry.serial_number, "x") for entry in crl}
    assert serials == {first.serial, second.serial}
    assert crl.issuer == x509.load_pem_x509_certificate(
        ca.intermediate_cert_pem.encode()
    ).subject


def test_crl_signature_verifies_against_intermediate(ca: LocalCA, leaf_key) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    ca.revoke(issued.serial)
    crl = x509.load_pem_x509_crl(ca.crl_pem().encode())
    intermediate = x509.load_pem_x509_certificate(ca.intermediate_cert_pem.encode())
    # Raises on failure; reaching the assert is the assertion.
    intermediate.public_key().verify(
        crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm)
    )
    assert crl.is_signature_valid(intermediate.public_key())


def test_empty_crl_is_still_valid(ca: LocalCA) -> None:
    crl = x509.load_pem_x509_crl(ca.crl_pem().encode())
    assert list(crl) == []


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_save_and_load_roundtrip(ca: LocalCA, leaf_key, tmp_path) -> None:
    issued = ca.issue(leaf_key.public_key(), ["a.test"])
    ca.revoke(issued.serial, reason="superseded")
    ca.save(tmp_path / "ca")

    for name in (CA_KEY_FILE, CA_CERT_FILE, INTERMEDIATE_CERT_FILE):
        assert (tmp_path / "ca" / name).exists()

    reloaded = LocalCA.load(tmp_path / "ca")
    assert reloaded.root_cert_pem == ca.root_cert_pem
    assert reloaded.intermediate_cert_pem == ca.intermediate_cert_pem
    assert reloaded.is_revoked(issued.serial)


def test_reloaded_ca_can_still_issue(ca: LocalCA, leaf_key, tmp_path) -> None:
    ca.save(tmp_path / "ca")
    reloaded = LocalCA.load(tmp_path / "ca")
    issued = reloaded.issue(leaf_key.public_key(), ["b.test"])
    assert len(verify_chain(issued.cert_pem, [issued.chain_pem], ca.root_cert_pem)) == 3


def test_issue_from_csr_preserves_public_key(ca: LocalCA, leaf_key) -> None:
    from acme_rehearsal.client import build_csr

    csr = build_csr(["csr.test"], leaf_key)
    issued = ca.issue_from_csr(
        x509.load_der_x509_csr(csr).public_bytes(serialization.Encoding.PEM).decode()
    )
    cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    assert cert.public_key().public_numbers() == leaf_key.public_key().public_numbers()
    assert issued.sans == ("csr.test",)


def test_issue_from_csr_rejects_missing_san(ca: LocalCA, leaf_key) -> None:
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
    )
    pem = (
        builder.sign(leaf_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    with pytest.raises(ValueError, match="subjectAltName"):
        ca.issue_from_csr(pem)
