"""A minimal but faithful ACME server (RFC 8555 subset) for rehearsal.

Scope is deliberate: this implements the endpoints a client needs to take a
certificate from "no account" to "installed chain", plus revocation. It does not
implement key rollover, external account binding, or ARI — pretending otherwise
would make the sandbox claim capabilities it lacks.

Fidelity notes, since the point of the exercise is that the rehearsal teaches
real behaviour:

* Every POST is a flattened JWS. Nonces are single-use. The ``url`` header must
  match the request URL, which is what stops a captured JWS being replayed at a
  different endpoint.
* ``POST-as-GET`` (empty payload) is required for reading resources, per
  RFC 8555 section 6.3.
* Problem documents use ``application/problem+json`` and the registered ACME
  error URNs.
* Challenges are validated synchronously. A production CA validates
  asynchronously; the state machine still passes through ``processing`` so the
  transcript shows the same sequence.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from cryptography import x509

from .ca import IssuedCertificate, LocalCA
from .challenges import (
    ChallengeResult,
    SandboxNetwork,
    validate_dns01,
    validate_http01,
)
from .protocol import (
    AcmeProblem,
    NonceStore,
    b64u,
    b64u_decode,
    jwk_thumbprint,
    public_key_from_jwk,
    verify_jws,
)

__all__ = ["AcmeServer", "Order", "RateLimiter"]

_CHALLENGE_TYPES = ("http-01", "dns-01")


@dataclass
class Order:
    id: str
    account_id: str
    identifiers: list[dict[str, str]]
    authz_ids: list[str] = field(default_factory=list)
    status: str = "pending"
    expires: str = ""
    cert_id: str | None = None
    error: dict[str, Any] | None = None

    def to_json(self, base: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "status": self.status,
            "expires": self.expires,
            "identifiers": self.identifiers,
            "authorizations": [f"{base}/authz/{aid}" for aid in self.authz_ids],
            "finalize": f"{base}/finalize/{self.id}",
        }
        if self.cert_id:
            body["certificate"] = f"{base}/cert/{self.cert_id}"
        if self.error:
            body["error"] = self.error
        return body


@dataclass
class Authorization:
    id: str
    account_id: str
    identifier: dict[str, str]
    status: str = "pending"
    challenge_ids: list[str] = field(default_factory=list)
    expires: str = ""

    def to_json(self, base: str, challenges: Mapping[str, Challenge]) -> dict[str, Any]:
        """Serialise per RFC 8555 7.1.4: ``challenges`` holds full objects, not URLs."""
        return {
            "status": self.status,
            "expires": self.expires,
            "identifier": self.identifier,
            "challenges": [
                challenges[cid].to_json(base) for cid in self.challenge_ids if cid in challenges
            ],
        }


@dataclass
class Challenge:
    id: str
    authz_id: str
    type: str
    token: str
    status: str = "pending"
    validated: str | None = None
    error: dict[str, Any] | None = None
    result: ChallengeResult | None = None

    def to_json(self, base: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": self.type,
            "url": f"{base}/chall/{self.id}",
            "status": self.status,
            "token": self.token,
        }
        if self.validated:
            body["validated"] = self.validated
        if self.error:
            body["error"] = self.error
        return body


class RateLimiter:
    """Fixed-window per-identifier issuance limiter.

    Exists because hitting a real CA's rate limit is one of the most expensive
    mistakes a learner can make, and it is invisible until it bites. In the
    sandbox the limit can be set low enough to demonstrate the failure in
    seconds.
    """

    def __init__(self, limit: int = 0, window_seconds: float = 7 * 24 * 3600) -> None:
        self.limit = limit
        self.window = window_seconds
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._clock = time.monotonic

    def check_and_record(self, identifier: str) -> tuple[bool, int]:
        """Return (allowed, remaining). A limit of 0 disables the limiter."""
        if self.limit <= 0:
            return True, -1
        now = self._clock()
        with self._lock:
            events = [t for t in self._events.get(identifier, []) if now - t < self.window]
            if len(events) >= self.limit:
                self._events[identifier] = events
                return False, 0
            events.append(now)
            self._events[identifier] = events
            return True, max(0, self.limit - len(events))

    def usage(self) -> dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self._events.items()}


class AcmeServer:
    """In-process ACME server bound to loopback.

    Start it, point a client at :attr:`directory_url`, stop it. All state is in
    memory; certificates are issued by the supplied :class:`LocalCA`.
    """

    def __init__(
        self,
        ca: LocalCA,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        network: SandboxNetwork | None = None,
        rate_limit: int = 0,
        leaf_validity_days: int = 90,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ca = ca
        self.network = network or SandboxNetwork()
        self.rate_limiter = RateLimiter(limit=rate_limit)
        self.leaf_validity_days = leaf_validity_days
        self._clock = clock
        self._host = host
        self._requested_port = port
        self._lock = threading.RLock()

        self.nonces = NonceStore()
        self.accounts: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, Order] = {}
        self.authzs: dict[str, Authorization] = {}
        self.challenges: dict[str, Challenge] = {}
        self.certificates: dict[str, IssuedCertificate] = {}
        self.events: list[dict[str, Any]] = []

        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._base_url = ""

    # -- lifecycle ---------------------------------------------------------

    @property
    def base_url(self) -> str:
        if not self._base_url:
            raise RuntimeError("server is not running")
        return self._base_url

    @property
    def directory_url(self) -> str:
        return f"{self.base_url}/directory"

    def start(self) -> str:
        handler = _make_handler(self)
        server = ThreadingHTTPServer((self._host, self._requested_port), handler)
        server.daemon_threads = True
        self._server = server
        port = server.server_address[1]
        self._base_url = f"http://{self._host}:{port}"
        self._thread = threading.Thread(
            target=server.serve_forever, name="rehearsal-acme", daemon=True
        )
        self._thread.start()
        return self.directory_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> AcmeServer:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    # -- helpers -----------------------------------------------------------

    def record(self, **event: Any) -> None:
        with self._lock:
            self.events.append({"at_ms": round(self._clock() * 1000, 3), **event})

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}{secrets.token_urlsafe(9)}"

    # -- resource creation -------------------------------------------------

    def create_account(
        self, jwk: Mapping[str, Any], contact: list[str] | None = None
    ) -> tuple[str, dict[str, Any]]:
        thumb = jwk_thumbprint(jwk)
        with self._lock:
            for account_id, account in self.accounts.items():
                if account["thumbprint"] == thumb:
                    # RFC 8555 7.3.1: returning an existing account is not an error.
                    return account_id, account
            account_id = self._new_id("a")
            account = {
                "id": account_id,
                "jwk": dict(jwk),
                "thumbprint": thumb,
                "contact": list(contact or []),
                "status": "valid",
                "created": self.ca._clock().isoformat(),  # noqa: SLF001 - same package
            }
            self.accounts[account_id] = account
            return account_id, account

    def create_order(self, account_id: str, identifiers: list[dict[str, str]]) -> Order:
        now = self.ca._clock()
        with self._lock:
            order_id = self._new_id("o")
            order = Order(
                id=order_id,
                account_id=account_id,
                identifiers=[dict(i) for i in identifiers],
                expires=(now.replace(microsecond=0) + _days(7)).isoformat(),
            )
            for identifier in order.identifiers:
                authz_id = self._new_id("z")
                authz = Authorization(
                    id=authz_id,
                    account_id=account_id,
                    identifier=dict(identifier),
                    expires=(now.replace(microsecond=0) + _days(7)).isoformat(),
                )
                for ctype in _CHALLENGE_TYPES:
                    chall_id = self._new_id("c")
                    self.challenges[chall_id] = Challenge(
                        id=chall_id,
                        authz_id=authz_id,
                        type=ctype,
                        token=b64u(secrets.token_bytes(24)),
                    )
                    authz.challenge_ids.append(chall_id)
                self.authzs[authz_id] = authz
                order.authz_ids.append(authz_id)
            self.orders[order_id] = order
            return order

    # -- validation --------------------------------------------------------

    def trigger_challenge(self, challenge: Challenge) -> ChallengeResult:
        """Validate a challenge and propagate the result up the state machine."""
        with self._lock:
            challenge.status = "processing"
            authz = self.authzs[challenge.authz_id]
            account = self.accounts[authz.account_id]
        self.record(
            event="challenge.validate",
            challenge=challenge.id,
            type=challenge.type,
            domain=authz.identifier["value"],
        )

        from .protocol import key_authorization

        key_auth = key_authorization(challenge.token, account["jwk"])
        if challenge.type == "http-01":
            result = validate_http01(
                domain=authz.identifier["value"],
                token=challenge.token,
                expected_key_authorization=key_auth,
                network=self.network,
            )
        else:
            result = validate_dns01(
                domain=authz.identifier["value"],
                key_authorization_value=key_auth,
                network=self.network,
            )

        with self._lock:
            challenge.result = result
            if result.ok:
                challenge.status = "valid"
                challenge.validated = self.ca._clock().isoformat()  # noqa: SLF001
                authz.status = "valid"
            else:
                challenge.status = "invalid"
                authz.status = "invalid"
                challenge.error = {
                    "type": "urn:ietf:params:acme:error:unauthorized",
                    "detail": result.detail,
                }
            self._refresh_order_for(authz)
        self.record(
            event="challenge.result",
            challenge=challenge.id,
            ok=result.ok,
            detail=result.detail,
        )
        return result

    def _refresh_order_for(self, authz: Authorization) -> None:
        for order in self.orders.values():
            if authz.id not in order.authz_ids:
                continue
            states = [self.authzs[aid].status for aid in order.authz_ids]
            if any(s == "invalid" for s in states):
                order.status = "invalid"
                order.error = {
                    "type": "urn:ietf:params:acme:error:unauthorized",
                    "detail": "one or more authorizations failed",
                }
            elif all(s == "valid" for s in states):
                if order.status == "pending":
                    order.status = "ready"

    def finalize(self, order: Order, csr_der: bytes) -> IssuedCertificate:
        """Sign the CSR and mark the order valid."""
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as exc:  # noqa: BLE001 - any parse failure is a bad CSR
            raise AcmeProblem("badCSR", f"CSR could not be parsed: {exc}") from exc
        if not csr.is_signature_valid:
            raise AcmeProblem("badCSR", "CSR signature is invalid")

        try:
            requested = [
                str(v).lower()
                for v in csr.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            ]
        except x509.ExtensionNotFound as exc:
            raise AcmeProblem("badCSR", "CSR has no subjectAltName extension") from exc

        authorized = {i["value"].lower() for i in order.identifiers}
        unauthorized = sorted(set(requested) - authorized)
        if unauthorized:
            raise AcmeProblem(
                "badCSR",
                f"CSR requests identifiers not present in the order: {unauthorized}",
                subproblems=[
                    {
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": f"{name} was not authorized by this order",
                        "identifier": {"type": "dns", "value": name},
                    }
                    for name in unauthorized
                ],
            )

        issued = self.ca.issue(csr.public_key(), requested, validity_days=self.leaf_validity_days)
        cert_id = self._new_id("x")
        with self._lock:
            self.certificates[cert_id] = issued
            order.cert_id = cert_id
            order.status = "valid"
        self.record(
            event="order.finalized",
            order=order.id,
            serial=issued.serial,
            sans=list(issued.sans),
        )
        return issued

    def revoke(self, cert_der: bytes, reason: int | None) -> str:
        cert = x509.load_der_x509_certificate(cert_der)
        serial = format(cert.serial_number, "x")
        reasons = {
            None: "unspecified",
            0: "unspecified",
            1: "keyCompromise",
            4: "superseded",
            5: "cessationOfOperation",
        }
        if reason not in reasons:
            raise AcmeProblem(
                "badRevocationReason", f"revocation reason {reason} is not permitted"
            )
        if self.ca.is_revoked(serial):
            raise AcmeProblem("alreadyRevoked", f"certificate {serial} is already revoked")
        self.ca.revoke(serial, reason=reasons[reason])
        self.record(event="cert.revoked", serial=serial, reason=reasons[reason])
        return serial


def _days(n: int):
    import datetime as _dt

    return _dt.timedelta(days=n)


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


def _make_handler(server_ref: AcmeServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RehearsalACME/1.0"
        protocol_version = "HTTP/1.1"

        # -- dispatch --------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_HEAD(self) -> None:  # noqa: N802
            self._dispatch("HEAD")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def log_message(self, *args: Any) -> None:
            """Suppress the default stderr access log; events go to the transcript."""

        def _dispatch(self, method: str) -> None:
            started = time.monotonic()
            path = urlparse(self.path).path
            status = 500
            try:
                status = self._route(method, path)
            except AcmeProblem as problem:
                status = problem.status
                self._send_problem(problem)
            except Exception as exc:  # noqa: BLE001 - never leak a traceback to a client
                status = 500
                self._send_problem(
                    AcmeProblem("serverInternal", f"{type(exc).__name__}: {exc}", status=500)
                )
            finally:
                server_ref.record(
                    event="http",
                    method=method,
                    path=path,
                    status=status,
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                )

        # -- routing ---------------------------------------------------

        def _route(self, method: str, path: str) -> int:
            base = server_ref.base_url
            if path == "/directory":
                if method != "GET":
                    raise AcmeProblem("malformed", "directory is GET-only", status=405)
                self._send_json(200, self._directory_document())
                return 200
            if path == "/new-nonce":
                if method not in ("HEAD", "GET"):
                    raise AcmeProblem("malformed", "new-nonce is HEAD or GET", status=405)
                self._send_empty(200)
                return 200
            if method != "POST":
                raise AcmeProblem("malformed", f"{path} requires POST", status=405)

            if path == "/new-account":
                return self._handle_new_account(base)
            if path == "/new-order":
                return self._handle_new_order(base)
            if path == "/revoke-cert":
                return self._handle_revoke()
            for prefix, handler in (
                ("/order/", self._handle_order),
                ("/authz/", self._handle_authz),
                ("/chall/", self._handle_challenge),
                ("/finalize/", self._handle_finalize),
                ("/cert/", self._handle_cert),
            ):
                if path.startswith(prefix):
                    return handler(base, path[len(prefix):])
            raise AcmeProblem("malformed", f"unknown endpoint {path}", status=404)

        def _directory_document(self) -> dict[str, Any]:
            base = server_ref.base_url
            return {
                "newNonce": f"{base}/new-nonce",
                "newAccount": f"{base}/new-account",
                "newOrder": f"{base}/new-order",
                "revokeCert": f"{base}/revoke-cert",
                "meta": {
                    "termsOfService": f"{base}/terms",
                    "website": f"{base}/",
                    "caaIdentities": ["rehearsal.invalid"],
                    "externalAccountRequired": False,
                    "isSandbox": True,
                },
            }

        # -- JWS -------------------------------------------------------

        def _read_jws(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise AcmeProblem("malformed", "empty request body")
            if length > 256 * 1024:
                raise AcmeProblem("malformed", "request body too large", status=413)
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AcmeProblem("malformed", f"body is not JSON: {exc}") from exc
            if not isinstance(body, dict):
                raise AcmeProblem("malformed", "JWS body must be a JSON object")
            return body

        def _verify(
            self, jws: Mapping[str, Any], *, allow_jwk: bool = False
        ) -> tuple[dict[str, Any], bytes, dict[str, Any] | None]:
            """Verify a JWS; returns (header, payload, account).

            ``allow_jwk`` is only true for new-account, where the key is being
            introduced. Every other endpoint must reference an existing account
            by ``kid``.
            """
            header = self._peek_header(jws)
            nonce = header.get("nonce")
            if not isinstance(nonce, str) or not server_ref.nonces.consume(nonce):
                raise AcmeProblem("badNonce", "nonce is missing, expired or already used")

            account: dict[str, Any] | None = None
            if allow_jwk and "jwk" in header:
                public_key = public_key_from_jwk(header["jwk"])
            else:
                kid = header.get("kid")
                if not isinstance(kid, str):
                    raise AcmeProblem("malformed", "JWS protected header lacks kid")
                account = self._account_from_kid(kid)
                public_key = public_key_from_jwk(account["jwk"])

            expected_url = server_ref.base_url + urlparse(self.path).path
            _header, payload = verify_jws(jws, public_key, expected_url=expected_url)
            return header, payload, account

        def _peek_header(self, jws: Mapping[str, Any]) -> dict[str, Any]:
            try:
                header = json.loads(b64u_decode(jws["protected"]))
            except (KeyError, ValueError, TypeError) as exc:
                raise AcmeProblem("malformed", "cannot decode JWS protected header") from exc
            if not isinstance(header, dict):
                raise AcmeProblem("malformed", "protected header must be an object")
            return header

        def _account_from_kid(self, kid: str) -> dict[str, Any]:
            parsed = urlparse(kid)
            if f"{parsed.scheme}://{parsed.netloc}" != server_ref.base_url:
                raise AcmeProblem("accountDoesNotExist", f"kid {kid!r} is not on this server")
            account_id = parsed.path.rsplit("/", 1)[-1]
            account = server_ref.accounts.get(account_id)
            if account is None:
                raise AcmeProblem("accountDoesNotExist", f"no account {account_id!r}")
            return account

        # -- endpoints -------------------------------------------------

        def _handle_new_account(self, base: str) -> int:
            jws = self._read_jws()
            header, payload, _ = self._verify(jws, allow_jwk=True)
            jwk = header.get("jwk")
            if not isinstance(jwk, dict):
                raise AcmeProblem("malformed", "new-account requires a jwk header")
            try:
                body = json.loads(payload) if payload else {}
            except json.JSONDecodeError as exc:
                raise AcmeProblem("malformed", f"payload is not JSON: {exc}") from exc

            account_id, account = server_ref.create_account(
                jwk, contact=body.get("contact") or []
            )
            server_ref.record(event="account.registered", account=account_id)
            self._send_json(
                201,
                {
                    "status": account["status"],
                    "contact": account["contact"],
                    "orders": f"{base}/acct/{account_id}/orders",
                },
                extra_headers={"Location": f"{base}/acct/{account_id}"},
            )
            return 201

        def _handle_new_order(self, base: str) -> int:
            jws = self._read_jws()
            _header, payload, account = self._verify(jws)
            try:
                body = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise AcmeProblem("malformed", f"payload is not JSON: {exc}") from exc
            identifiers = body.get("identifiers")
            if not isinstance(identifiers, list) or not identifiers:
                raise AcmeProblem("malformed", "order must contain identifiers")

            cleaned: list[dict[str, str]] = []
            for entry in identifiers:
                if not isinstance(entry, dict):
                    raise AcmeProblem("malformed", "identifier must be an object")
                itype = entry.get("type")
                value = entry.get("value")
                if itype != "dns":
                    raise AcmeProblem(
                        "unsupportedIdentifier", f"identifier type {itype!r} is not supported"
                    )
                if not isinstance(value, str) or not value.strip():
                    raise AcmeProblem("malformed", "identifier value must be a non-empty string")
                value = value.strip().lower()
                if "*" in value:
                    raise AcmeProblem(
                        "rejectedIdentifier", "wildcards are not supported in the sandbox"
                    )
                allowed, remaining = server_ref.rate_limiter.check_and_record(value)
                if not allowed:
                    raise AcmeProblem(
                        "rateLimited",
                        f"too many orders for {value} in the current window",
                        status=429,
                        identifier={"type": "dns", "value": value},
                    )
                cleaned.append({"type": "dns", "value": value})

            order = server_ref.create_order(account["id"], cleaned)  # type: ignore[index]
            server_ref.record(
                event="order.created",
                order=order.id,
                identifiers=[i["value"] for i in cleaned],
            )
            self._send_json(
                201,
                order.to_json(base),
                extra_headers={"Location": f"{base}/order/{order.id}"},
            )
            return 201

        def _handle_order(self, base: str, order_id: str) -> int:
            self._require_post_as_get()
            order = server_ref.orders.get(order_id)
            if order is None:
                raise AcmeProblem("malformed", f"no order {order_id!r}", status=404)
            self._send_json(200, order.to_json(base))
            return 200

        def _handle_authz(self, base: str, authz_id: str) -> int:
            self._require_post_as_get()
            authz = server_ref.authzs.get(authz_id)
            if authz is None:
                raise AcmeProblem("malformed", f"no authorization {authz_id!r}", status=404)
            self._send_json(200, authz.to_json(base, server_ref.challenges))
            return 200

        def _handle_challenge(self, base: str, challenge_id: str) -> int:
            jws = self._read_jws()
            _header, payload, _account = self._verify(jws)
            challenge = server_ref.challenges.get(challenge_id)
            if challenge is None:
                raise AcmeProblem("malformed", f"no challenge {challenge_id!r}", status=404)

            if payload:
                try:
                    body = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise AcmeProblem("malformed", f"payload is not JSON: {exc}") from exc
                if body.get("keyAuthorization") is not None:
                    raise AcmeProblem(
                        "malformed",
                        "keyAuthorization is not accepted; it is derived from the account key",
                    )
                server_ref.trigger_challenge(challenge)
            self._send_json(200, challenge.to_json(base))
            return 200

        def _handle_finalize(self, base: str, order_id: str) -> int:
            jws = self._read_jws()
            _header, payload, _account = self._verify(jws)
            order = server_ref.orders.get(order_id)
            if order is None:
                raise AcmeProblem("malformed", f"no order {order_id!r}", status=404)
            if order.status == "invalid":
                raise AcmeProblem("orderNotReady", "order is invalid")
            if order.status not in ("ready", "processing"):
                raise AcmeProblem(
                    "orderNotReady",
                    f"order is {order.status!r}; authorizations must be valid first",
                )
            try:
                body = json.loads(payload)
                csr_der = b64u_decode(body["csr"])
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise AcmeProblem("badCSR", f"finalize payload is invalid: {exc}") from exc

            server_ref.finalize(order, csr_der)
            self._send_json(200, order.to_json(base))
            return 200

        def _handle_cert(self, base: str, cert_id: str) -> int:
            self._require_post_as_get()
            issued = server_ref.certificates.get(cert_id)
            if issued is None:
                raise AcmeProblem("malformed", f"no certificate {cert_id!r}", status=404)
            # RFC 8555: the default chain is application/pem-certificate-chain.
            self._send_raw(
                200,
                issued.fullchain_pem.encode("ascii"),
                "application/pem-certificate-chain",
            )
            return 200

        def _handle_revoke(self) -> int:
            jws = self._read_jws()
            _header, payload, _account = self._verify(jws)
            try:
                body = json.loads(payload)
                cert_der = b64u_decode(body["certificate"])
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise AcmeProblem("malformed", f"revoke payload is invalid: {exc}") from exc
            server_ref.revoke(cert_der, body.get("reason"))
            self._send_empty(200)
            return 200

        def _require_post_as_get(self) -> None:
            jws = self._read_jws()
            _header, payload, _account = self._verify(jws)
            if payload:
                raise AcmeProblem(
                    "malformed", "this resource must be fetched with POST-as-GET (empty payload)"
                )

        # -- responses -------------------------------------------------

        def _common_headers(self) -> dict[str, str]:
            return {"Replay-Nonce": server_ref.nonces.issue(), "Cache-Control": "no-store"}

        def _send_json(
            self,
            status: int,
            body: Mapping[str, Any],
            *,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._common_headers()}
            if extra_headers:
                headers.update(extra_headers)
            self._write(status, data, headers)

        def _send_raw(self, status: int, data: bytes, content_type: str) -> None:
            headers = {"Content-Type": content_type, **self._common_headers()}
            self._write(status, data, headers)

        def _send_empty(self, status: int) -> None:
            self._write(status, b"", self._common_headers())

        def _send_problem(self, problem: AcmeProblem) -> None:
            data = json.dumps(problem.to_dict(), sort_keys=True).encode("utf-8")
            headers = {
                "Content-Type": "application/problem+json",
                **self._common_headers(),
            }
            self._write(problem.status, data, headers)

        def _write(self, status: int, data: bytes, headers: Mapping[str, str]) -> None:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data and self.command != "HEAD":
                self.wfile.write(data)

    return Handler
