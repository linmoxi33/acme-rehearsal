"""Challenge solving and validation inside the sandbox.

Two challenge types are implemented because they exercise different failure
modes, and both are what learners actually hit in production:

* **HTTP-01** — the sandbox starts a real HTTP listener on loopback and the
  *server* performs a real HTTP GET back to it, with the ``Host`` header set to
  the requested domain. Only name resolution is simulated. The request is a
  genuine TCP round trip, so a learner watching the transcript sees the same
  shape of failure they would see against Let's Encrypt (404, wrong body,
  connection refused).
* **DNS-01** — records live in :class:`SandboxNetwork`, standing in for an
  authoritative DNS server. DNS is a lookup by nature, so a table is a faithful
  model rather than a shortcut.

Failure injection is first-class: teaching material needs the broken path as
much as the happy path.
"""

from __future__ import annotations

import http.client
import http.server
import threading
from dataclasses import dataclass, field
from typing import Any

from .protocol import b64u, dns01_txt_value

__all__ = [
    "ChallengeResult",
    "Dns01Solver",
    "Http01Solver",
    "SandboxNetwork",
    "validate_dns01",
    "validate_http01",
]

#: Bounded read so a hostile or broken listener cannot stall the validator.
_MAX_RESPONSE_BYTES = 64 * 1024
_DEFAULT_TIMEOUT = 5.0


class SandboxNetwork:
    """The sandbox's stand-in for DNS plus its routing table.

    ``http_routes`` maps a domain to a loopback listener; ``txt_records`` maps a
    fully-qualified record name to its values. Both are plain dicts behind a lock
    because the server validates on worker threads.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._http_routes: dict[str, tuple[str, int]] = {}
        self._txt: dict[str, list[str]] = {}
        self._resolve_log: list[dict[str, Any]] = []

    # -- HTTP-01 routing ---------------------------------------------------

    def register_http(self, domain: str, host: str, port: int) -> None:
        with self._lock:
            self._http_routes[domain.lower()] = (host, port)

    def unregister_http(self, domain: str) -> None:
        with self._lock:
            self._http_routes.pop(domain.lower(), None)

    def resolve_http(self, domain: str) -> tuple[str, int] | None:
        with self._lock:
            route = self._http_routes.get(domain.lower())
            self._resolve_log.append({"domain": domain, "route": route})
        return route

    # -- DNS-01 records ----------------------------------------------------

    def set_txt(self, name: str, values: list[str]) -> None:
        with self._lock:
            self._txt[name.lower()] = list(values)

    def add_txt(self, name: str, value: str) -> None:
        with self._lock:
            self._txt.setdefault(name.lower(), []).append(value)

    def get_txt(self, name: str) -> list[str]:
        with self._lock:
            values = list(self._txt.get(name.lower(), []))
            self._resolve_log.append({"name": name, "txt_count": len(values)})
        return values

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "http_routes": {k: list(v) for k, v in self._http_routes.items()},
                "txt_records": {k: list(v) for k, v in self._txt.items()},
                "lookups": len(self._resolve_log),
            }


@dataclass
class ChallengeResult:
    """Outcome of a validation attempt, with the evidence needed to explain it."""

    ok: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "detail": self.detail, "evidence": dict(self.evidence)}


# --------------------------------------------------------------------------
# HTTP-01
# --------------------------------------------------------------------------


class _ChallengeHandler(http.server.BaseHTTPRequestHandler):
    """Serves ``/.well-known/acme-challenge/<token>`` from the owning solver."""

    server_version = "RehearsalSandbox/1.0"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        solver: Http01Solver = self.server.solver  # type: ignore[attr-defined]
        prefix = "/.well-known/acme-challenge/"
        if not self.path.startswith(prefix):
            self._respond(404, b"not found")
            return
        token = self.path[len(prefix):].split("?")[0]
        body = solver.lookup(token)
        if body is None:
            self._respond(404, b"token not found")
            return
        self._respond(200, body.encode("ascii"))

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:  # noqa: D102 - silence stderr spam
        solver: Http01Solver = self.server.solver  # type: ignore[attr-defined]
        solver.requests.append({"path": self.path, "client": self.client_address[0]})


class Http01Solver:
    """A loopback HTTP listener that answers ACME challenge tokens."""

    def __init__(self, *, host: str = "127.0.0.1") -> None:
        self._host = host
        self._tokens: dict[str, str] = {}
        self._lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._failure_mode: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> int:
        """Start listening and return the bound port (0 => ephemeral)."""
        server = http.server.ThreadingHTTPServer((self._host, 0), _ChallengeHandler)
        server.daemon_threads = True
        server.solver = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="rehearsal-http01", daemon=True
        )
        self._thread.start()
        return server.server_address[1]

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> Http01Solver:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    # -- tokens ------------------------------------------------------------

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Http01Solver is not started")
        return self._server.server_address[1]

    def set_token(self, token: str, key_authorization_value: str) -> None:
        with self._lock:
            self._tokens[token] = key_authorization_value

    def lookup(self, token: str) -> str | None:
        """Return the body to serve, honouring the injected failure mode."""
        with self._lock:
            value = self._tokens.get(token)
        if value is None:
            return None
        if self._failure_mode == "wrong_token":
            return b64u(b"deliberately-wrong-key-authorization")
        return value

    def inject_failure(self, mode: str | None) -> None:
        """Make the listener misbehave on purpose.

        ``wrong_token`` returns a body that does not match the expected key
        authorization; ``no_server`` makes the solver refuse to start so the
        validator sees a connection error.
        """
        if mode not in (None, "wrong_token", "no_server"):
            raise ValueError(f"unknown failure mode {mode!r}")
        self._failure_mode = mode


def validate_http01(
    *,
    domain: str,
    token: str,
    expected_key_authorization: str,
    network: SandboxNetwork,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ChallengeResult:
    """Perform the ACME HTTP-01 validation.

    This opens a real TCP connection to the loopback listener registered for
    ``domain`` and sends ``Host: <domain>``. A missing route is reported as
    ``dns`` failure, a refused connection as ``connection``, and a body mismatch
    as ``unauthorized`` — mirroring the problem types a real CA returns.
    """
    route = network.resolve_http(domain)
    if route is None:
        return ChallengeResult(
            False,
            f"no route registered for {domain}",
            {"stage": "dns", "domain": domain},
        )
    host, port = route
    path = f"/.well-known/acme-challenge/{token}"
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    evidence: dict[str, Any] = {
        "stage": "http",
        "domain": domain,
        "url": f"http://{host}:{port}{path}",
        "host_header": domain,
    }
    try:
        connection.request("GET", path, headers={"Host": domain})
        response = connection.getresponse()
        body = response.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        evidence["status"] = response.status
        evidence["body_length"] = len(body)
    except (OSError, http.client.HTTPException) as exc:
        return ChallengeResult(
            False,
            f"connection to {host}:{port} failed: {exc}",
            {**evidence, "stage": "connection", "error": type(exc).__name__},
        )
    finally:
        connection.close()

    if response.status != 200:
        return ChallengeResult(
            False,
            f"expected HTTP 200, got {response.status}",
            {**evidence, "failure": "status"},
        )
    if body.strip() != expected_key_authorization.strip():
        return ChallengeResult(
            False,
            "key authorization mismatch",
            {**evidence, "failure": "unauthorized", "received_length": len(body.strip())},
        )
    return ChallengeResult(True, "key authorization verified over HTTP", evidence)


# --------------------------------------------------------------------------
# DNS-01
# --------------------------------------------------------------------------


class Dns01Solver:
    """Writes ``_acme-challenge.<domain>`` TXT records into the sandbox network."""

    def __init__(self, network: SandboxNetwork) -> None:
        self._network = network
        self._published: list[tuple[str, str]] = []

    def publish(self, domain: str, key_authorization_value: str) -> str:
        name = f"_acme-challenge.{domain.lower()}"
        value = dns01_txt_value(key_authorization_value)
        self._network.add_txt(name, value)
        self._published.append((name, value))
        return name

    def withdraw_all(self) -> None:
        for name, _value in self._published:
            self._network.set_txt(name, [])
        self._published.clear()

    @property
    def published(self) -> list[tuple[str, str]]:
        return list(self._published)


def validate_dns01(
    *,
    domain: str,
    key_authorization_value: str,
    network: SandboxNetwork,
) -> ChallengeResult:
    """Check that the expected TXT digest is present at ``_acme-challenge.<domain>``."""
    name = f"_acme-challenge.{domain.lower()}"
    expected = dns01_txt_value(key_authorization_value)
    values = network.get_txt(name)
    evidence = {
        "stage": "dns",
        "record": name,
        "expected_digest": expected,
        "observed_count": len(values),
    }
    if not values:
        return ChallengeResult(False, f"no TXT record at {name}", evidence)
    if expected not in values:
        return ChallengeResult(
            False, f"TXT record at {name} does not contain the expected digest", evidence
        )
    return ChallengeResult(True, f"TXT record at {name} verified", evidence)
