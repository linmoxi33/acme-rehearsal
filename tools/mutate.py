"""Mutation testing harness.

Rationale: a green suite proves the tests run, not that they would notice a
defect. This script injects deliberate faults into the source, re-runs the *full*
suite for each, and reports which faults survive.

Two rules learned the hard way, both enforced here:

1. **Compare the set of failing tests, not the count.** A mutation that makes one
   test fail and another pass is not killed; it is a change in behaviour that the
   suite does not understand.
2. **Restore and verify by hash.** A killed run leaves the tree mutated. Every
   file is snapshotted before the first mutation and re-verified after the last,
   and any mismatch aborts the run rather than silently shipping a broken tree.

While this runs, do not commit, push, or run any other writer against the working
tree: the mutations are live source edits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "acme_rehearsal"

#: On-disk backups. A mutation run that is killed (Ctrl-C, OOM, terminal closed)
#: leaves the tree mutated; the next invocation restores from here before doing
#: anything else. This is not belt-and-braces: it happened once, and a mutated
#: ``transcript.py`` survived into a full test run before being noticed.
BACKUP_DIR = ROOT / ".mutation-backups"


def ensure_clean_start() -> list[str]:
    """Restore any files left mutated by an interrupted run.

    Returns the names restored. Called before the baseline snapshot so a stale
    backup can never be mistaken for the baseline.
    """
    if not BACKUP_DIR.exists():
        return []
    restored: list[str] = []
    for backup in sorted(BACKUP_DIR.glob("*.py.orig")):
        target = SRC / backup.name[: -len(".orig")]
        target.write_bytes(backup.read_bytes())
        backup.unlink()
        restored.append(target.name)
    if not restored:
        BACKUP_DIR.rmdir()
    return restored

# Each mutant is (id, file, original snippet, replacement, note).
# Snippets are exact substrings of the current source; a miss is reported, never
# guessed at.
MUTANTS: list[tuple[str, str, str, str, str]] = [
    (
        "M01",
        "guard.py",
        "        if lowered in self._denied:",
        "        if False:",
        "public CA denylist disabled",
    ),
    (
        "M02",
        "guard.py",
        "        if _is_loopback_host(host) and self._allow_loopback:",
        "        if True:",
        "every destination treated as loopback",
    ),
    (
        "M03",
        "guard.py",
        "        if self.enforce and not _is_within(resolved, self.root):",
        "        if False:",
        "write-scope enforcement disabled",
    ),
    (
        "M04",
        "guard.py",
        '        "identical": not (added or removed or changed),',
        '        "identical": True,',
        "snapshot diff always reports identical",
    ),
    (
        "M05",
        "protocol.py",
        "    return b64u(hashlib.sha256(_canonical_json_bytes(canonical)).digest())",
        '    return b64u(hashlib.sha256(b64u(_canonical_json_bytes(canonical)).encode("ascii")).digest())',
        "thumbprint double-encodes the canonical JSON",
    ),
    (
        "M06",
        "protocol.py",
        "            if nonce in self._issued:\n                del self._issued[nonce]",
        "            if nonce in self._issued:",
        "nonces become reusable",
    ),
    (
        "M07",
        "protocol.py",
        '    if expected_url is not None and header.get("url") != expected_url:',
        "    if False:",
        "JWS url binding removed",
    ),
    (
        "M08",
        "protocol.py",
        "    except InvalidSignature as exc:\n"
        '        raise AcmeProblem("unauthorized", "JWS signature verification failed") from exc',
        "    except InvalidSignature as exc:\n        pass",
        "invalid signatures accepted",
    ),
    (
        "M09",
        "server.py",
        '            "challenges": [\n'
        "                challenges[cid].to_json(base) for cid in self.challenge_ids if cid in challenges\n"
        "            ],",
        '            "challenges": [f"{base}/chall/{cid}" for cid in self.challenge_ids],',
        "authorization returns challenge URLs instead of objects",
    ),
    (
        "M10",
        "server.py",
        '            if order.status not in ("ready", "processing"):',
        "            if False:",
        "finalize accepts orders that are not ready",
    ),
    (
        "M11",
        "server.py",
        "        if unauthorized:",
        "        if False:",
        "CSR may request identifiers outside the order",
    ),
    (
        "M12",
        "server.py",
        "                if not allowed:",
        "                if False:",
        "rate limiter never rejects",
    ),
    (
        "M13",
        "ca.py",
        "        if not _signature_ok(current, candidate):",
        "        if False:",
        "chain links not signature-checked",
    ),
    (
        "M14",
        "ca.py",
        "        self._revoked[serial] = {\n"
        '            "serial": serial,\n'
        '            "reason": reason,\n'
        '            "revoked_at": self._clock().isoformat(),\n'
        "        }",
        "        pass",
        "revocation not recorded",
    ),
    (
        "M15",
        "store.py",
        "        return max(existing, default=0) + 1",
        "        return 1",
        "archive version never increments",
    ),
    (
        "M16",
        "preview.py",
        "    return max(0, value // 24) if unit.startswith(\"hour\") else value",
        "    return 0",
        "renewal threshold always zero",
    ),
    (
        "M17",
        "rehearsal.py",
        "        snapshot_diff = (\n"
        "            diff_snapshots(before_snapshot, after_snapshot)\n"
        "            if before_snapshot and after_snapshot\n"
        "            else None\n"
        "        )",
        "        snapshot_diff = None",
        "real config snapshot never compared",
    ),
    (
        "M18",
        "transcript.py",
        '                "passed": blocked == 0 and not non_loopback_allowed,',
        '                "passed": True,',
        "egress verdict always passes",
    ),
    (
        "M19",
        "transcript.py",
        '                "passed": not escapes and bool(filesystem.get("enforced", False)),',
        '                "passed": True,',
        "write-scope verdict always passes",
    ),
    (
        "M20",
        "client.py",
        '                if problem.error_type == "badNonce" and attempt == 0:',
        "                if False:",
        "client never retries a bad nonce",
    ),
    (
        "M21",
        "transcript.py",
        '                    "passed": bool(snapshot_diff.get("identical")),',
        '                    "passed": True,',
        "real-config verdict always passes",
    ),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_tree() -> dict[str, str]:
    return {p.name: sha256(p) for p in sorted(SRC.glob("*.py"))}


def run_suite(python: str) -> tuple[set[str], float]:
    """Run the full suite and return (failing test ids, seconds elapsed)."""
    started = time.monotonic()
    completed = subprocess.run(
        [
            python,
            "-m",
            "pytest",
            "tests/",
            "-q",
            "--tb=no",
            "-p",
            "no:cacheprovider",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    elapsed = time.monotonic() - started
    failures = {
        line.split(" ", 1)[1].strip()
        for line in completed.stdout.splitlines()
        if line.startswith("FAILED ")
    }
    if completed.returncode not in (0, 1):
        # Collection error or interpreter crash: treat as a hard failure so the
        # harness does not silently score it as "killed".
        failures.add(f"__harness_error__:{completed.returncode}")
    return failures, elapsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inject faults and measure detection.")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--only", nargs="*", default=None, help="subset of mutant ids")
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="skip the baseline run (only safe when a prior batch already proved it clean)",
    )
    args = parser.parse_args(argv)

    recovered = ensure_clean_start()
    if recovered:
        print(f"RECOVERED from an interrupted run: {recovered}", flush=True)

    baseline_hashes = snapshot_tree()
    print(f"snapshotted {len(baseline_hashes)} source files", flush=True)

    if args.skip_baseline:
        baseline_failures: set[str] = set()
        print("baseline skipped (--skip-baseline)", flush=True)
    else:
        print("running baseline suite...", flush=True)
        baseline_failures, baseline_seconds = run_suite(args.python)
        if baseline_failures:
            print(f"baseline is not clean: {sorted(baseline_failures)}", flush=True)
            print("refusing to score mutations against a failing baseline", flush=True)
            return 2
        print(f"baseline clean in {baseline_seconds:.1f}s", flush=True)

    selected = [m for m in MUTANTS if not args.only or m[0] in args.only]
    results: list[dict] = []
    survivors: list[str] = []

    for mutant_id, filename, original, replacement, note in selected:
        path = SRC / filename
        text = path.read_text(encoding="utf-8")
        if original not in text:
            print(f"{mutant_id} SKIP (snippet not found in {filename})", flush=True)
            results.append(
                {"id": mutant_id, "file": filename, "note": note, "status": "snippet-missing"}
            )
            continue

        mutated = text.replace(original, replacement, 1)
        if mutated == text:
            print(f"{mutant_id} SKIP (replacement is a no-op)", flush=True)
            results.append(
                {"id": mutant_id, "file": filename, "note": note, "status": "no-op"}
            )
            continue

        # Persist the original before touching the source, so an interruption at
        # any later point is recoverable on the next start.
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = BACKUP_DIR / f"{filename}.orig"
        backup.write_bytes(path.read_bytes())
        path.write_text(mutated, encoding="utf-8", newline="\n")
        try:
            failures, elapsed = run_suite(args.python)
        finally:
            path.write_bytes(backup.read_bytes())
            backup.unlink()
            if not any(BACKUP_DIR.iterdir()):
                BACKUP_DIR.rmdir()

        restored = sha256(path)
        if restored != baseline_hashes[filename]:
            print(
                f"{mutant_id} ABORT: {filename} did not restore cleanly "
                f"({restored} != {baseline_hashes[filename]})",
                flush=True,
            )
            return 3

        newly_failing = sorted(failures - baseline_failures)
        killed = bool(newly_failing)
        if not killed:
            survivors.append(mutant_id)
        status = "killed" if killed else "SURVIVED"
        print(
            f"{mutant_id} {status:<9} {len(newly_failing):>2} new failure(s) "
            f"in {elapsed:.0f}s  [{note}]",
            flush=True,
        )
        for test_id in newly_failing[:3]:
            print(f"        - {test_id}", flush=True)
        results.append(
            {
                "id": mutant_id,
                "file": filename,
                "note": note,
                "status": "killed" if killed else "survived",
                "new_failures": newly_failing,
            }
        )

    final_hashes = snapshot_tree()
    if final_hashes != baseline_hashes:
        print("ABORT: source tree differs from baseline after mutation run", flush=True)
        for name, digest in final_hashes.items():
            if baseline_hashes.get(name) != digest:
                print(f"  changed: {name}", flush=True)
        return 4

    killed_count = sum(1 for r in results if r["status"] == "killed")
    scored = [r for r in results if r["status"] in ("killed", "survived")]
    print(
        f"\n{len(scored)} mutants scored, {killed_count} killed, "
        f"{len(survivors)} survived",
        flush=True,
    )
    if survivors:
        print(f"survivors: {survivors}", flush=True)
    print("source tree verified identical to baseline", flush=True)

    if args.json_out:
        args.json_out.write_text(
            json.dumps(
                {
                    "scored": len(scored),
                    "killed": killed_count,
                    "survived": survivors,
                    "results": results,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return 0 if not survivors else 1


if __name__ == "__main__":
    raise SystemExit(main())
