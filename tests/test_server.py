"""Server tests: state machine, JWS enforcement, and error taxonomy.

Each test drives the server through the real HTTP surface rather than calling
internal methods, so the assertions cover routing, JWS verification and status
codes together — the same path a client takes.
"""

from __future__ import annotations

import json

import pytest

from acme_rehearsal.ca import LocalCA
from acme_rehearsal.challenges import Http01Solver, SandboxNetwork
from acme_rehearsal.client import AcmeClient, build_csr, generate_account_key, generate_leaf_key
from acme_rehearsal.protocol import AcmeProblem, b64u, sign_jws
from acme_rehearsal.server import AcmeServer


class Env:
    def __init__(self, *, rate_limit: int = 0) -> None:
        self.ca = LocalCA.create()
        self.network = SandboxNetwork()
        self.solver = Http01Solver()
        self.port = self.solver.start()
        self.network.register_http("a.test", "127.0.0.1", self.port)
        self.server = AcmeServer(self.ca, network=self.network, rate_limit=rate_limit)
        self.directory_url = self.server.start()
        self.key = generate_account_key()
        self.client = AcmeClient(self.directory_url, self.key)
        self.client.fetch_directory()
        self.account_url = self.client.register()

    def close(self) -> None:
        self.solver.stop()
        self.server.stop()

    def solve_order(self, domains: list[str]) -> dict:
        """Create an order, validate every authorization, return the ready order.

        The returned dict keeps ``_url`` so callers can finalize *this* order
        rather than creating a second, unvalidated one.
        """
        order = self.client.new_order(domains)
        for authz_url in order["authorizations"]:
            authz = self.client.fetch(authz_url)
            challenge = next(c for c in authz["challenges"] if c["type"] == "http-01")
            from acme_rehearsal.protocol import key_authorization

            self.solver.set_token(
                challenge["token"], key_authorization(challenge["token"], self.client._jwk)
            )
            self.client.respond_challenge(challenge["url"])
        final = self.client.fetch(order["_url"])
        final["_url"] = order["_url"]
        return final


@pytest.fixture
def env():
    instance = Env()
    try:
        yield instance
    finally:
        instance.close()


# --------------------------------------------------------------------------
# Directory and account
# --------------------------------------------------------------------------


def test_directory_exposes_required_endpoints(env: Env) -> None:
    directory = env.client.fetch_directory()
    for key in ("newNonce", "newAccount", "newOrder", "revokeCert"):
        assert key in directory
    assert directory["meta"]["isSandbox"] is True


def test_new_account_returns_location(env: Env) -> None:
    assert env.account_url.startswith(env.server.base_url + "/acct/")


def test_second_registration_returns_same_account(env: Env) -> None:
    """RFC 8555 7.3.1: re-registering the same key is not an error."""
    second = AcmeClient(env.directory_url, env.key)
    second.fetch_directory()
    assert second.register() == env.account_url


def test_unknown_kid_is_rejected(env: Env) -> None:
    other = AcmeClient(env.directory_url, generate_account_key())
    other.fetch_directory()
    other._kid = env.server.base_url + "/acct/doesnotexist"  # noqa: SLF001
    with pytest.raises(AcmeProblem) as exc:
        other.new_order(["a.test"])
    assert exc.value.error_type == "accountDoesNotExist"


# --------------------------------------------------------------------------
# Nonces and JWS
# --------------------------------------------------------------------------


def test_replayed_nonce_is_rejected(env: Env) -> None:
    """Single-use nonces are the whole point; a replay must be a badNonce."""
    env.client._nonce = None  # noqa: SLF001
    env.client._refresh_nonce()  # noqa: SLF001
    nonce = env.client._nonce  # noqa: SLF001
    url = env.server.base_url + "/new-order"
    payload = {"identifiers": [{"type": "dns", "value": "a.test"}]}

    first = sign_jws(
        env.key, {"alg": "ES256", "nonce": nonce, "url": url, "kid": env.account_url}, payload
    )
    status, _h, _d = env.client._request(  # noqa: SLF001
        "POST", url, body=json.dumps(first).encode(), headers={"Content-Type": "application/jose+json"}
    )
    assert status == 201

    second = sign_jws(
        env.key, {"alg": "ES256", "nonce": nonce, "url": url, "kid": env.account_url}, payload
    )
    status, _h, data = env.client._request(  # noqa: SLF001
        "POST", url, body=json.dumps(second).encode(), headers={"Content-Type": "application/jose+json"}
    )
    assert status == 400
    assert json.loads(data)["type"].endswith("badNonce")


def test_client_retries_once_after_bad_nonce(env: Env) -> None:
    """Every real ACME client must recover from a stale nonce exactly once."""
    env.client._nonce = "stale-nonce-value"  # noqa: SLF001
    order = env.client.new_order(["a.test"])
    assert order["status"] == "pending"
    assert env.client.bad_nonce_retries == 1


def test_client_gives_up_after_a_second_bad_nonce(env: Env) -> None:
    """Retrying forever would hide a server that never issues usable nonces."""
    original_request = env.client._request  # noqa: SLF001

    def request_with_stale_nonce(method, url, **kwargs):
        status, headers, data = original_request(method, url, **kwargs)
        if method == "POST":
            # Force the next signature to reuse a consumed nonce.
            env.client._nonce = "stale-nonce-value"  # noqa: SLF001
        return status, headers, data

    env.client._nonce = "stale-nonce-value"  # noqa: SLF001
    env.client._request = request_with_stale_nonce  # noqa: SLF001
    try:
        with pytest.raises(AcmeProblem) as exc:
            env.client.new_order(["a.test"])
        assert exc.value.error_type == "badNonce"
        assert env.client.bad_nonce_retries == 1
    finally:
        env.client._request = original_request  # noqa: SLF001


def test_jws_url_must_match_endpoint(env: Env) -> None:
    env.client._nonce = None  # noqa: SLF001
    env.client._refresh_nonce()  # noqa: SLF001
    url = env.server.base_url + "/new-order"
    jws = sign_jws(
        env.key,
        {
            "alg": "ES256",
            "nonce": env.client._nonce,  # noqa: SLF001
            "url": env.server.base_url + "/revoke-cert",  # wrong endpoint
            "kid": env.account_url,
        },
        {"identifiers": [{"type": "dns", "value": "a.test"}]},
    )
    status, _h, data = env.client._request(  # noqa: SLF001
        "POST", url, body=json.dumps(jws).encode(), headers={"Content-Type": "application/jose+json"}
    )
    assert status == 400
    assert json.loads(data)["type"].endswith("unauthorized")


def test_post_as_get_required_for_reads(env: Env) -> None:
    """Sending a non-empty payload to a read endpoint must be rejected."""
    order = env.client.new_order(["a.test"])
    env.client._nonce = None  # noqa: SLF001
    env.client._refresh_nonce()  # noqa: SLF001
    url = order["_url"]
    jws = sign_jws(
        env.key,
        {"alg": "ES256", "nonce": env.client._nonce, "url": url, "kid": env.account_url},  # noqa: SLF001
        {"unexpected": True},
    )
    status, _h, data = env.client._request(  # noqa: SLF001
        "POST", url, body=json.dumps(jws).encode(), headers={"Content-Type": "application/jose+json"}
    )
    assert status == 400
    assert "POST-as-GET" in json.loads(data)["detail"]


# --------------------------------------------------------------------------
# Authorization shape
# --------------------------------------------------------------------------


def test_authorization_returns_full_challenge_objects(env: Env) -> None:
    """RFC 8555 7.1.4: challenges are objects, not URL strings.

    A server that returns URLs here breaks every client that reads
    ``challenge["token"]`` without a second fetch.
    """
    order = env.client.new_order(["a.test"])
    authz = env.client.fetch(order["authorizations"][0])
    assert isinstance(authz["challenges"], list)
    for challenge in authz["challenges"]:
        assert isinstance(challenge, dict), "challenge entries must be objects"
        assert set(challenge) >= {"type", "url", "status", "token"}
        assert challenge["type"] in ("http-01", "dns-01")


def test_authorization_offers_both_challenge_types(env: Env) -> None:
    order = env.client.new_order(["a.test"])
    authz = env.client.fetch(order["authorizations"][0])
    assert {c["type"] for c in authz["challenges"]} == {"http-01", "dns-01"}


# --------------------------------------------------------------------------
# Order state machine
# --------------------------------------------------------------------------


def test_order_starts_pending_then_becomes_ready(env: Env) -> None:
    order = env.client.new_order(["a.test"])
    assert order["status"] == "pending"
    ready = env.solve_order(["a.test"])
    assert ready["status"] == "ready"


def test_finalize_before_authorization_is_rejected(env: Env) -> None:
    order = env.client.new_order(["a.test"])
    leaf = generate_leaf_key(key_type="ec")
    csr = build_csr(["a.test"], leaf)
    with pytest.raises(AcmeProblem) as exc:
        env.client.finalize(order["finalize"], csr)
    assert exc.value.error_type == "orderNotReady"


def test_finalize_with_extra_domain_is_rejected(env: Env) -> None:
    order = env.solve_order(["a.test"])
    leaf = generate_leaf_key(key_type="ec")
    csr = build_csr(["a.test", "evil.test"], leaf)
    with pytest.raises(AcmeProblem) as exc:
        env.client.finalize(order["finalize"], csr)
    assert exc.value.error_type == "badCSR"
    assert "not present in the order" in exc.value.detail


def test_wildcard_identifier_is_rejected(env: Env) -> None:
    with pytest.raises(AcmeProblem) as exc:
        env.client.new_order(["*.a.test"])
    assert exc.value.error_type == "rejectedIdentifier"


def test_non_dns_identifier_is_rejected(env: Env) -> None:
    env.client._nonce = None  # noqa: SLF001
    env.client._refresh_nonce()  # noqa: SLF001
    url = env.server.base_url + "/new-order"
    jws = sign_jws(
        env.key,
        {"alg": "ES256", "nonce": env.client._nonce, "url": url, "kid": env.account_url},  # noqa: SLF001
        {"identifiers": [{"type": "ip", "value": "10.0.0.1"}]},
    )
    status, _h, data = env.client._request(  # noqa: SLF001
        "POST", url, body=json.dumps(jws).encode(), headers={"Content-Type": "application/jose+json"}
    )
    assert status == 400
    assert json.loads(data)["type"].endswith("unsupportedIdentifier")


# --------------------------------------------------------------------------
# Challenge validation
# --------------------------------------------------------------------------


def test_failed_http01_marks_authorization_invalid(env: Env) -> None:
    order = env.client.new_order(["a.test"])
    authz_url = order["authorizations"][0]
    authz = env.client.fetch(authz_url)
    challenge = next(c for c in authz["challenges"] if c["type"] == "http-01")
    # Publish a deliberately wrong key authorization.
    env.solver.set_token(challenge["token"], "wrong-value")
    env.client.respond_challenge(challenge["url"])
    final = env.client.fetch(authz_url)
    assert final["status"] == "invalid"
    assert env.client.fetch(order["_url"])["status"] == "invalid"


def test_missing_route_fails_as_dns_stage(env: Env) -> None:
    order = env.client.new_order(["unrouted.test"])
    authz = env.client.fetch(order["authorizations"][0])
    challenge = next(c for c in authz["challenges"] if c["type"] == "http-01")
    env.client.respond_challenge(challenge["url"])
    assert env.client.fetch(order["authorizations"][0])["status"] == "invalid"
    results = [
        e for e in env.server.events if e.get("event") == "challenge.result"
    ]
    assert results and "no route" in results[-1]["detail"]


def test_dns01_succeeds_when_txt_is_published(env: Env) -> None:
    from acme_rehearsal.challenges import Dns01Solver
    from acme_rehearsal.protocol import key_authorization

    order = env.client.new_order(["a.test"])
    authz_url = order["authorizations"][0]
    authz = env.client.fetch(authz_url)
    challenge = next(c for c in authz["challenges"] if c["type"] == "dns-01")
    solver = Dns01Solver(env.network)
    solver.publish("a.test", key_authorization(challenge["token"], env.client._jwk))  # noqa: SLF001
    env.client.respond_challenge(challenge["url"])
    assert env.client.fetch(authz_url)["status"] == "valid"


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


def test_rate_limit_trips_after_configured_issuances() -> None:
    instance = Env(rate_limit=1)
    try:
        instance.client.new_order(["a.test"])
        with pytest.raises(AcmeProblem) as exc:
            instance.client.new_order(["a.test"])
        assert exc.value.error_type == "rateLimited"
        assert exc.value.status == 429
    finally:
        instance.close()


def test_rate_limit_is_per_identifier() -> None:
    instance = Env(rate_limit=1)
    try:
        instance.client.new_order(["a.test"])
        # A different name is unaffected.
        instance.client.new_order(["b.test"])
    finally:
        instance.close()


# --------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------


def test_revoke_records_serial_and_second_revoke_fails(env: Env) -> None:
    from acme_rehearsal.client import certificate_der

    order = env.solve_order(["a.test"])
    leaf = generate_leaf_key(key_type="ec")
    order = env.client.finalize(order["finalize"], build_csr(["a.test"], leaf))
    pem = env.client.fetch_raw(order["certificate"]).decode()
    leaf_pem = pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    der = certificate_der(leaf_pem)

    env.client.revoke(der, reason=4)
    assert len(env.ca.revoked_serials) == 1

    with pytest.raises(AcmeProblem) as exc:
        env.client.revoke(der, reason=4)
    assert exc.value.error_type == "alreadyRevoked"


def test_invalid_revocation_reason_is_rejected(env: Env) -> None:
    from acme_rehearsal.client import certificate_der

    order = env.solve_order(["a.test"])
    leaf = generate_leaf_key(key_type="ec")
    order = env.client.finalize(order["finalize"], build_csr(["a.test"], leaf))
    pem = env.client.fetch_raw(order["certificate"]).decode()
    leaf_pem = pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"

    with pytest.raises(AcmeProblem) as exc:
        env.client.revoke(certificate_der(leaf_pem), reason=9)
    assert exc.value.error_type == "badRevocationReason"


# --------------------------------------------------------------------------
# Unknown routes
# --------------------------------------------------------------------------


def test_unknown_endpoint_returns_404(env: Env) -> None:
    status, _h, _d = env.client._request("POST", env.server.base_url + "/nope")  # noqa: SLF001
    assert status == 404


def test_get_on_post_endpoint_is_rejected(env: Env) -> None:
    status, _h, _d = env.client._request("GET", env.server.base_url + "/new-order")  # noqa: SLF001
    assert status == 405


def test_b64u_roundtrip_used_by_csr_encoding(env: Env) -> None:
    leaf = generate_leaf_key(key_type="ec")
    csr = build_csr(["a.test"], leaf)
    assert b64u(csr)  # non-empty, no padding
    assert "=" not in b64u(csr)
