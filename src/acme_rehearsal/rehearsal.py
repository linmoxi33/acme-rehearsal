"""Rehearsal orchestration: run a certificate lifecycle end to end, contained.

The orchestrator owns the sandbox lifecycle:

1. create an isolated root and a fresh CA inside it,
2. enter the egress guard and the filesystem guard,
3. start the ACME server on loopback and drive a client against it,
4. store the result in certbot's layout,
5. verify the chain independently,
6. exit the guards and emit a transcript whose verdict is computed from evidence.

Failure scenarios are first-class. A teaching tool that can only show the happy
path teaches nothing about the mistakes that cost money.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509

from .ca import LocalCA, verify_chain
from .challenges import Http01Solver, SandboxNetwork
from .client import (
    AcmeClient,
    build_csr,
    chain_parts,
    generate_account_key,
    generate_leaf_key,
)
from .guard import (
    EgressGuard,
    FilesystemGuard,
    diff_snapshots,
    directory_snapshot,
)
from .preview import Previewer
from .protocol import AcmeProblem, key_authorization
from .server import AcmeServer
from .store import CertStore
from .transcript import Recorder

__all__ = ["Rehearsal", "RehearsalConfig", "RehearsalOutcome"]

SCENARIOS = (
    "issue",
    "renew",
    "revoke",
    "failure-http01",
    "failure-ratelimit",
    "failure-badcsr",
)


@dataclass
class RehearsalConfig:
    domains: list[str] = field(default_factory=lambda: ["demo.example.test"])
    challenge_type: str = "http-01"
    workdir: Path | None = None
    account_key_type: str = "ec"
    leaf_key_type: str = "rsa"
    leaf_validity_days: int = 90
    rate_limit: int = 0
    real_config_dir: Path | None = None
    run_openssl: bool = True
    keep_workdir: bool = True

    def resolved_workdir(self) -> Path:
        if self.workdir is not None:
            return Path(self.workdir).resolve()
        return Path(tempfile.mkdtemp(prefix="acme-rehearsal-")).resolve()


@dataclass
class RehearsalOutcome:
    scenario: str
    workdir: Path
    transcript: dict[str, Any]
    lineage: dict[str, Any] | None = None
    certificate: dict[str, Any] | None = None
    transcript_path: Path | None = None

    @property
    def passed(self) -> bool:
        return bool(self.transcript.get("verdict", {}).get("passed"))


class Rehearsal:
    """Runs one scenario inside a fresh sandbox."""

    def __init__(self, config: RehearsalConfig) -> None:
        self.config = config
        self.workdir = config.resolved_workdir()
        self.sandbox = self.workdir / "sandbox"
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self.recorder = Recorder(config.domains[0] if config.domains else "unknown")
        # Multi-stage scenarios (renew, revoke) run more than one guarded window.
        # Evidence must be merged across all of them, otherwise the verdict only
        # covers the last stage and the guarantee is silently narrowed.
        self._egress_reports: list[dict[str, Any]] = []
        self._fs_reports: list[dict[str, Any]] = []

    # -- evidence accumulation ---------------------------------------------

    def _accumulate(self, egress: EgressGuard, fs_guard: FilesystemGuard) -> None:
        self._egress_reports.append(egress.report())
        self._fs_reports.append(fs_guard.report())

    def _merged_egress(self) -> dict[str, Any]:
        attempts: list[dict[str, Any]] = []
        for report in self._egress_reports:
            attempts.extend(report.get("attempts", []))
        blocked = sum(1 for a in attempts if not a.get("allowed"))
        return {
            "stages": len(self._egress_reports),
            "total_attempts": len(attempts),
            "blocked_count": blocked,
            "outbound_connections": sum(
                1 for a in attempts if a.get("kind") == "connect" and a.get("allowed")
            ),
            "attempts": attempts,
            "verdict": "no-egress" if blocked == 0 else "egress-attempted",
        }

    def _merged_filesystem(self) -> dict[str, Any]:
        writes: list[dict[str, Any]] = []
        for report in self._fs_reports:
            writes.extend(report.get("writes", []))
        return {
            "root": str(self.sandbox),
            "enforced": True,
            "write_count": len(writes),
            "total_bytes": sum(int(w.get("bytes", 0)) for w in writes),
            "writes": writes,
        }

    # -- public entry points ----------------------------------------------

    def run(self, scenario: str) -> RehearsalOutcome:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; choose from {SCENARIOS}")
        if scenario == "issue":
            return self._run_issue()
        if scenario == "renew":
            return self._run_renew()
        if scenario == "revoke":
            return self._run_revoke()
        if scenario == "failure-http01":
            return self._run_issue(failure_mode="http01", expect_error="unauthorized")
        if scenario == "failure-ratelimit":
            # A limit of one, pre-consumed, so the very next order trips it.
            self.config.rate_limit = 1
            return self._run_issue(failure_mode="ratelimit", expect_error="rateLimited")
        return self._run_issue(failure_mode="badcsr", expect_error="badCSR")

    # -- core flows --------------------------------------------------------

    def _run_issue(
        self, *, failure_mode: str | None = None, expect_error: str | None = None
    ) -> RehearsalOutcome:
        cfg = self.config
        recorder = self.recorder
        recorder.inputs = {
            "domains": list(cfg.domains),
            "challenge_type": cfg.challenge_type,
            "workdir": str(self.workdir),
            "sandbox_root": str(self.sandbox),
            "leaf_validity_days": cfg.leaf_validity_days,
            "rate_limit": cfg.rate_limit,
            "failure_mode": failure_mode,
            "real_config_dir": str(cfg.real_config_dir) if cfg.real_config_dir else None,
        }

        # A snapshot taken *before* the guard is installed, so it reflects the
        # real directory as the user left it.
        before_snapshot = (
            directory_snapshot(cfg.real_config_dir) if cfg.real_config_dir else None
        )

        fs_guard = FilesystemGuard(self.sandbox)
        egress = EgressGuard()
        chain_report: dict[str, Any] | None = None
        cert_info: dict[str, Any] | None = None
        lineage_info: dict[str, Any] | None = None
        error_info: dict[str, Any] | None = None
        client: AcmeClient | None = None

        with egress:
            with recorder.step("setup", "create-local-ca") as step:
                ca = LocalCA.create()
                ca.save(self.sandbox / "ca")
                step.output = {
                    "root_subject": _subject_of(ca.root_cert_pem),
                    "intermediate_subject": _subject_of(ca.intermediate_cert_pem),
                }
                step.evidence = {
                    "root_ca": str(self.sandbox / "ca" / "root-ca.cert.pem"),
                    "trust_scope": "sandbox directory only",
                }

            network = SandboxNetwork()
            solver = Http01Solver() if cfg.challenge_type == "http-01" else None
            server = AcmeServer(
                ca,
                network=network,
                rate_limit=cfg.rate_limit,
                leaf_validity_days=cfg.leaf_validity_days,
            )
            directory_url = server.start()
            recorder.add(
                "setup",
                "start-acme-server",
                output={"directory_url": directory_url},
                evidence={"bind": server.base_url, "scope": "loopback only"},
            )
            if failure_mode == "ratelimit":
                # Simulate "this domain already issued once this week" so the
                # limit of one trips on the order this rehearsal is about to make.
                server.rate_limiter.check_and_record(cfg.domains[0])
                recorder.note(
                    "pre-consumed one issuance for the domain to reproduce a rate limit"
                )

            try:
                if solver is not None:
                    port = solver.start()
                    for domain in cfg.domains:
                        network.register_http(domain, "127.0.0.1", port)
                    recorder.add(
                        "setup",
                        "start-http01-listener",
                        output={"port": port, "routes": list(cfg.domains)},
                        evidence={"note": "server will perform a real HTTP GET back to this port"},
                    )

                account_key = generate_account_key(key_type=cfg.account_key_type)
                client = AcmeClient(directory_url, account_key)

                with recorder.step("acme", "fetch-directory") as step:
                    directory = client.fetch_directory()
                    step.output = {"endpoints": sorted(directory)}
                    step.evidence = {"directory_url": directory_url}

                with recorder.step("acme", "new-account") as step:
                    account_url = client.register()
                    step.output = {"account_url": account_url}
                    step.evidence = {"key_type": cfg.account_key_type}

                with recorder.step(
                    "acme", "new-order", input={"identifiers": cfg.domains}
                ) as step:
                    order = client.new_order(cfg.domains)
                    step.output = {
                        "order_url": order.get("_url"),
                        "status": order.get("status"),
                        "authorizations": order.get("authorizations"),
                    }

                order_url = order["_url"]
                for authz_url in order["authorizations"]:
                    self._solve_authorization(
                        client=client,
                        server=server,
                        solver=solver,
                        authz_url=authz_url,
                        failure_mode=failure_mode,
                    )

                with recorder.step("acme", "poll-order-ready") as step:
                    order = client.fetch(order_url)
                    step.output = {"status": order.get("status")}
                    if order.get("status") not in ("ready", "valid"):
                        raise AcmeProblem(
                            "orderNotReady",
                            f"order is {order.get('status')!r} after authorization",
                        )

                leaf_key = generate_leaf_key(key_type=cfg.leaf_key_type)
                csr_domains = (
                    list(cfg.domains) + ["not-in-order.example.test"]
                    if failure_mode == "badcsr"
                    else list(cfg.domains)
                )
                csr_der = build_csr(csr_domains, leaf_key)
                with recorder.step(
                    "acme", "finalize", input={"csr_domains": csr_domains}
                ) as step:
                    order = client.finalize(order["finalize"], csr_der)
                    step.output = {"status": order.get("status")}
                    step.evidence = {"csr_bytes": len(csr_der), "key_type": cfg.leaf_key_type}

                with recorder.step("acme", "download-certificate") as step:
                    fullchain = client.fetch_raw(order["certificate"]).decode("ascii")
                    leaf_pem, chain_pem = chain_parts(fullchain)
                    step.output = {
                        "chain_blocks": fullchain.count("-----BEGIN CERTIFICATE-----"),
                        "leaf_bytes": len(leaf_pem),
                    }

                cert_info = _certificate_summary(leaf_pem)
                with recorder.step("verify", "walk-chain") as step:
                    visited = verify_chain(leaf_pem, [chain_pem], ca.root_cert_pem)
                    chain_report = {
                        "ok": True,
                        "detail": " -> ".join(visited),
                        "path": visited,
                    }
                    step.output = chain_report

                if cfg.run_openssl:
                    chain_report = self._openssl_verify(
                        leaf_pem, chain_pem, ca.root_cert_pem, chain_report
                    )

                with recorder.step("store", "write-lineage") as step:
                    store = CertStore(self.sandbox / "etc", fs_guard)
                    lineage = store.save_lineage(
                        issued=_issued_from_parts(leaf_pem, chain_pem, csr_domains),
                        private_key_pem=_private_pem(leaf_key),
                        server=directory_url,
                        account_id=_account_id(account_url),
                        key_type=cfg.leaf_key_type,
                    )
                    lineage_info = lineage.to_dict()
                    step.output = lineage_info
                    step.evidence = {
                        "live_layout": sorted(p.name for p in lineage.live_dir.iterdir()),
                        "link_mode": lineage.link_mode,
                    }
                    if lineage.link_mode != "symlink":
                        recorder.note(
                            "live/ entries are copies rather than symlinks: creating "
                            "symlinks needs Developer Mode or elevation on Windows"
                        )

                with recorder.step("store", "read-back") as step:
                    reloaded = store.get(lineage.domain)
                    days = store.days_remaining(lineage) if reloaded else None
                    step.output = {
                        "lineage_found": reloaded is not None,
                        "domains": reloaded.domains if reloaded else [],
                        "days_remaining": days,
                    }

            except AcmeProblem as problem:
                error_info = {
                    "type": problem.error_type,
                    "urn": problem.urn,
                    "detail": problem.detail,
                    "status": problem.status,
                }
                recorder.note(f"scenario stopped at ACME error: {problem.error_type}")
            finally:
                if solver is not None:
                    solver.stop()
                server.stop()

        after_snapshot = (
            directory_snapshot(cfg.real_config_dir) if cfg.real_config_dir else None
        )
        snapshot_diff = (
            diff_snapshots(before_snapshot, after_snapshot)
            if before_snapshot and after_snapshot
            else None
        )

        self._accumulate(egress, fs_guard)
        transcript = recorder.finish(
            egress=self._merged_egress(),
            filesystem=self._merged_filesystem(),
            snapshot_diff=snapshot_diff,
            chain=chain_report,
            result={
                "certificate": cert_info,
                "lineage": lineage_info,
                "error": error_info,
                "server_events": server.events,
                "client_steps": client.steps if client is not None else [],
            },
        )
        return self._finish(
            "issue" if failure_mode is None else f"failure-{failure_mode}",
            transcript,
            lineage_info,
            cert_info,
            expect_error=expect_error,
        )

    def _solve_authorization(
        self,
        *,
        client: AcmeClient,
        server: AcmeServer,
        solver: Http01Solver | None,
        authz_url: str,
        failure_mode: str | None,
    ) -> None:
        recorder = self.recorder
        with recorder.step("acme", "fetch-authorization", input={"url": authz_url}) as step:
            authz = client.fetch(authz_url)
            step.output = {
                "status": authz.get("status"),
                "identifier": authz.get("identifier"),
                "challenges": len(authz.get("challenges", [])),
            }

        domain = authz["identifier"]["value"]
        challenge_url = _pick_challenge(authz, self.config.challenge_type)
        if challenge_url is None:
            raise AcmeProblem(
                "malformed",
                f"authorization for {domain} offers no {self.config.challenge_type} challenge",
            )
        challenge = client.fetch(challenge_url)

        with recorder.step(
            "challenge",
            "publish-response",
            input={"type": challenge["type"], "domain": domain, "token": challenge["token"]},
        ) as step:
            account_jwk = client._jwk  # noqa: SLF001 - same package, needed for key auth
            key_auth = key_authorization(challenge["token"], account_jwk)
            if challenge["type"] == "http-01":
                if solver is None:
                    raise AcmeProblem("malformed", "http-01 selected but no solver is running")
                solver.set_token(challenge["token"], key_auth)
                if failure_mode == "http01":
                    solver.inject_failure("wrong_token")
                    recorder.note("injected fault: listener serves a wrong key authorization")
                step.output = {
                    "served_at": f"http://127.0.0.1:{solver.port}/.well-known/acme-challenge/"
                    f"{challenge['token'][:12]}...",
                    "key_authorization_length": len(key_auth),
                }
            else:
                from .challenges import Dns01Solver

                dns_solver = Dns01Solver(server.network)
                record = dns_solver.publish(domain, key_auth)
                step.output = {"record": record}

        with recorder.step(
            "challenge", "trigger-validation", input={"url": challenge_url}
        ) as step:
            updated = client.respond_challenge(challenge_url)
            step.output = {"status": updated.get("status"), "error": updated.get("error")}
            step.evidence = {
                "server_events": [
                    e for e in server.events if e.get("event", "").startswith("challenge")
                ]
            }

        with recorder.step("challenge", "poll-authorization") as step:
            final = client.fetch(authz_url)
            step.output = {"status": final.get("status")}
            if final.get("status") != "valid":
                detail = updated.get("error", {}).get("detail", "authorization did not validate")
                raise AcmeProblem("unauthorized", detail)

    def _run_renew(self) -> RehearsalOutcome:
        """Issue (if needed) then renew, so one command shows both halves.

        The first issuance uses a one-day lifetime on purpose: ``certbot renew``
        only acts on certificates inside their renewal window (30 days by
        default), so a 90-day certificate would be skipped and the rehearsal
        would demonstrate nothing. A near-expiry certificate makes the preview's
        decision — and the subsequent renewal — visible.
        """
        cfg = self.config
        store_path = self.sandbox / "etc"
        fs_guard = FilesystemGuard(self.sandbox)
        store = CertStore(store_path, fs_guard)
        existing = store.list_lineages()

        original_validity = cfg.leaf_validity_days
        cfg.leaf_validity_days = 1
        try:
            first = self._run_issue()
        finally:
            cfg.leaf_validity_days = original_validity
        if not first.passed:
            return first

        recorder = self.recorder
        egress = EgressGuard()
        before_snapshot = (
            directory_snapshot(cfg.real_config_dir) if cfg.real_config_dir else None
        )
        lineage_info: dict[str, Any] | None = None
        chain_report: dict[str, Any] | None = None
        with egress:
            with recorder.step("renew", "load-lineage") as step:
                lineages = store.list_lineages()
                step.output = {
                    "lineages": [ln.domain for ln in lineages],
                    "preexisting": [ln.domain for ln in existing],
                }
                if not lineages:
                    raise RuntimeError("no lineage available to renew")
                lineage = lineages[0]

            with recorder.step("renew", "preview-impact") as step:
                preview = Previewer(store_path).preview_renew()
                step.output = preview.to_dict()
                step.evidence = {"read_only": True}

            with recorder.step("renew", "reissue") as step:
                ca = LocalCA.load(self.sandbox / "ca")
                network = SandboxNetwork()
                solver = Http01Solver()
                port = solver.start()
                for domain in lineage.domains:
                    network.register_http(domain, "127.0.0.1", port)
                server = AcmeServer(
                    ca, network=network, leaf_validity_days=cfg.leaf_validity_days
                )
                server.start()
                try:
                    account_key = generate_account_key(key_type=cfg.account_key_type)
                    client = AcmeClient(server.directory_url, account_key)
                    client.fetch_directory()
                    account_url = client.register()
                    order = client.new_order(lineage.domains)
                    for authz_url in order["authorizations"]:
                        self._solve_authorization(
                            client=client,
                            server=server,
                            solver=solver,
                            authz_url=authz_url,
                            failure_mode=None,
                        )
                    leaf_key = generate_leaf_key(key_type=cfg.leaf_key_type)
                    csr_der = build_csr(lineage.domains, leaf_key)
                    order = client.finalize(order["finalize"], csr_der)
                    fullchain = client.fetch_raw(order["certificate"]).decode("ascii")
                    leaf_pem, chain_pem = chain_parts(fullchain)
                    visited = verify_chain(leaf_pem, [chain_pem], ca.root_cert_pem)
                    chain_report = {"ok": True, "detail": " -> ".join(visited)}
                    renewed = store.save_lineage(
                        issued=_issued_from_parts(leaf_pem, chain_pem, lineage.domains),
                        private_key_pem=_private_pem(leaf_key),
                        server=server.directory_url,
                        account_id=_account_id(account_url),
                        key_type=cfg.leaf_key_type,
                        lineage_name=lineage.domain,
                    )
                    lineage_info = renewed.to_dict()
                    step.output = {
                        "version_before": lineage.version,
                        "version_after": renewed.version,
                        "server": server.directory_url,
                    }
                    step.evidence = {
                        "archive_files": sorted(p.name for p in renewed.archive_dir.iterdir())
                    }
                finally:
                    solver.stop()
                    server.stop()

            with recorder.step("renew", "confirm-version-bump") as step:
                final = store.get(lineage.domain)
                step.output = {
                    "version": final.version if final else None,
                    "link_mode": final.link_mode if final else None,
                }
                if final is None or final.version <= lineage.version:
                    raise RuntimeError("renewal did not create a new archive version")

        after_snapshot = (
            directory_snapshot(cfg.real_config_dir) if cfg.real_config_dir else None
        )
        snapshot_diff = (
            diff_snapshots(before_snapshot, after_snapshot)
            if before_snapshot and after_snapshot
            else None
        )
        self._accumulate(egress, fs_guard)
        transcript = recorder.finish(
            egress=self._merged_egress(),
            filesystem=self._merged_filesystem(),
            snapshot_diff=snapshot_diff,
            chain=chain_report,
            result={"lineage": lineage_info, "first_run": first.transcript.get("result")},
        )
        return self._finish("renew", transcript, lineage_info, first.certificate)

    def _run_revoke(self) -> RehearsalOutcome:
        """Issue, then revoke, and show the CA's revocation list change."""
        first = self._run_issue()
        if not first.passed:
            return first

        recorder = self.recorder
        egress = EgressGuard()
        fs_guard = FilesystemGuard(self.sandbox)
        revoked: dict[str, Any] | None = None
        with egress:
            with recorder.step("revoke", "load-certificate") as step:
                store = CertStore(self.sandbox / "etc", fs_guard)
                lineage = store.get(self.config.domains[0])
                if lineage is None:
                    raise RuntimeError("no lineage to revoke")
                from .client import certificate_der

                cert_der = certificate_der(lineage.cert_path.read_text(encoding="utf-8"))
                step.output = {"domain": lineage.domain, "der_bytes": len(cert_der)}

            with recorder.step("revoke", "preview-impact") as step:
                preview = Previewer(self.sandbox / "etc").preview_revoke()
                step.output = preview.to_dict()

            with recorder.step("revoke", "call-revoke-cert") as step:
                ca = LocalCA.load(self.sandbox / "ca")
                server = AcmeServer(ca)
                server.start()
                try:
                    account_key = generate_account_key(key_type=self.config.account_key_type)
                    client = AcmeClient(server.directory_url, account_key)
                    client.fetch_directory()
                    client.register()
                    client.revoke(cert_der, reason=4)
                    # Revocation lives in the CA object; persist it so the CRL
                    # survives a reload. Without this the "confirm" step below
                    # would load a CA with an empty revocation list.
                    ca.save(self.sandbox / "ca")
                    revoked = {"serial": _serial_of(cert_der), "reason": "superseded"}
                    step.output = revoked
                    step.evidence = {
                        "crl_entries": len(ca.revoked_serials),
                        "crl_issuer": _subject_of(ca.intermediate_cert_pem),
                    }
                finally:
                    server.stop()

            with recorder.step("revoke", "confirm-crl") as step:
                ca = LocalCA.load(self.sandbox / "ca")
                crl = ca.crl_pem()
                step.output = {
                    "revoked_serials": list(ca.revoked_serials),
                    "crl_blocks": crl.count("-----BEGIN X509 CRL-----"),
                }

        self._accumulate(egress, fs_guard)
        transcript = recorder.finish(
            egress=self._merged_egress(),
            filesystem=self._merged_filesystem(),
            snapshot_diff=None,
            # Revocation does not produce a new chain, so no chain check applies.
            chain=None,
            result={"revoked": revoked},
        )
        return self._finish("revoke", transcript, None, first.certificate)

    # -- helpers -----------------------------------------------------------

    def _openssl_verify(
        self,
        leaf_pem: str,
        chain_pem: str,
        root_pem: str,
        chain_report: dict[str, Any],
    ) -> dict[str, Any]:
        """Independently verify the chain with the system openssl.

        A second implementation is the point: if only our own verifier accepts
        the chain, the chain is not trustworthy.
        """
        openssl = shutil.which("openssl")
        if openssl is None:
            self.recorder.add(
                "verify",
                "openssl-verify",
                status="skipped",
                output={"reason": "openssl not on PATH"},
            )
            return {**chain_report, "openssl": {"ok": None, "detail": "openssl not found"}}

        base = self.sandbox / "verify"
        base.mkdir(parents=True, exist_ok=True)
        leaf_path = base / "leaf.pem"
        chain_path = base / "chain.pem"
        root_path = base / "root.pem"
        pairs = (
            (leaf_path, leaf_pem),
            (chain_path, chain_pem),
            (root_path, root_pem),
        )
        for path, content in pairs:
            path.write_text(content, encoding="utf-8", newline="\n")

        with self.recorder.step("verify", "openssl-verify") as step:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    openssl,
                    "verify",
                    "-CAfile",
                    str(root_path),
                    "-untrusted",
                    str(chain_path),
                    str(leaf_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            ok = completed.returncode == 0
            step.output = {
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
            step.status = "ok" if ok else "failed"
        return {
            **chain_report,
            "openssl": {
                "ok": ok,
                "detail": (completed.stdout or completed.stderr).strip(),
            },
            "ok": bool(chain_report.get("ok")) and ok,
        }

    def _finish(
        self,
        scenario: str,
        transcript: dict[str, Any],
        lineage: dict[str, Any] | None,
        certificate: dict[str, Any] | None,
        *,
        expect_error: str | None = None,
    ) -> RehearsalOutcome:
        """Attach the failure-scenario check, then persist the transcript.

        A fault-injection scenario is only meaningful if the *expected* error
        actually appeared. Without this check a broken injection would look like
        a pass: the sandbox stayed contained, so every containment check is green.
        """
        if expect_error:
            error = (transcript.get("result") or {}).get("error") or {}
            observed = error.get("type")
            checks = transcript["verdict"]["checks"]
            checks.append(
                {
                    "name": "expected_error_observed",
                    "passed": observed == expect_error,
                    "detail": f"expected {expect_error!r}, observed {observed!r}",
                }
            )
            transcript["verdict"]["passed"] = all(c["passed"] for c in checks)

        transcript_path = self.workdir / "transcript.json"
        transcript_path.write_text(
            json.dumps(transcript, indent=2) + "\n", encoding="utf-8"
        )
        return RehearsalOutcome(
            scenario=scenario,
            workdir=self.workdir,
            transcript=transcript,
            lineage=lineage,
            certificate=certificate,
            transcript_path=transcript_path,
        )


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _pick_challenge(authz: Mapping[str, Any], wanted: str) -> str | None:
    for challenge in authz.get("challenges", []):
        if challenge.get("type") == wanted:
            return challenge.get("url")
    return None


def _subject_of(pem: str) -> str:
    return x509.load_pem_x509_certificate(pem.encode("ascii")).subject.rfc4514_string()


def _serial_of(der: bytes) -> str:
    return format(x509.load_der_x509_certificate(der).serial_number, "x")


def _certificate_summary(leaf_pem: str) -> dict[str, Any]:
    cert = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    from cryptography.hazmat.primitives import hashes

    try:
        sans = [
            str(v)
            for v in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        ]
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
    }


def _private_pem(key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _issued_from_parts(leaf_pem: str, chain_pem: str, domains: Iterable[str]):
    from .ca import IssuedCertificate

    cert = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    return IssuedCertificate(
        cert_pem=leaf_pem,
        chain_pem=chain_pem,
        fullchain_pem=leaf_pem + chain_pem,
        key_pem="",
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=tuple(domains),
    )


def _account_id(account_url: str) -> str:
    return account_url.rstrip("/").rsplit("/", 1)[-1]
