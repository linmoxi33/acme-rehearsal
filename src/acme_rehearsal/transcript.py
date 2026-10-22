"""Rehearsal transcript: the record of what happened and the proof it was contained.

A rehearsal that produces a certificate but cannot show *how* is not teaching
material. Every step is captured with its input, output, status, duration and
whatever evidence makes the step checkable afterwards.

The ``verdict`` block is computed, not written by hand. Each check maps to a
machine-observable fact:

============================  =============================================
check                         evidence
============================  =============================================
``no_egress``                 egress guard blocked zero attempts and every
                              allowed connection targeted loopback
``sandbox_writes_only``       every recorded write resolves under the root
``real_config_untouched``     before/after directory snapshots are identical
``chain_verifies``            leaf -> intermediate -> root walks clean
``no_public_ca_contact``      no attempt against a known public CA hostname
============================  =============================================
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["Recorder", "Step", "SCHEMA_VERSION"]

SCHEMA_VERSION = "acme-rehearsal/1"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Step:
    """One observable action inside a rehearsal."""

    index: int
    phase: str
    action: str
    status: str = "ok"
    input: Any = None
    output: Any = None
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: str | None = None
    started_at: str = ""
    _t0: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "index": self.index,
            "phase": self.phase,
            "action": self.action,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 3),
            "started_at": self.started_at,
        }
        if self.input is not None:
            payload["input"] = _truncate(self.input)
        if self.output is not None:
            payload["output"] = _truncate(self.output)
        if self.evidence:
            payload["evidence"] = _truncate(self.evidence)
        if self.error:
            payload["error"] = self.error
        return payload


def _truncate(value: Any, *, limit: int = 4000) -> Any:
    """Keep the transcript readable: clip long strings and deep structures."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"... [{len(value) - limit} chars clipped]"
    if isinstance(value, Mapping):
        return {k: _truncate(v, limit=limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_truncate(v, limit=limit) for v in value]
    return value


class Recorder:
    """Collects steps and produces the final transcript document."""

    def __init__(self, scenario: str, *, clock=time.monotonic) -> None:
        self.scenario = scenario
        self.started_at = _iso_now()
        self.steps: list[Step] = []
        self.inputs: dict[str, Any] = {}
        self.containment: dict[str, Any] = {}
        self.result: dict[str, Any] = {}
        self.notes: list[str] = []
        self._clock = clock
        self._t0 = clock()

    # -- recording ---------------------------------------------------------

    @contextmanager
    def step(
        self,
        phase: str,
        action: str,
        *,
        input: Any = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> Iterator[Step]:
        """Time a block and record it, including failures.

        A raised exception is recorded with ``status="failed"`` and re-raised: a
        transcript that silently omits the step that broke is worse than no
        transcript.
        """
        step = Step(
            index=len(self.steps) + 1,
            phase=phase,
            action=action,
            input=input,
            evidence=dict(evidence or {}),
            started_at=_iso_now(),
            _t0=self._clock(),
        )
        try:
            yield step
        except Exception as exc:
            step.status = "failed"
            step.error = f"{type(exc).__name__}: {exc}"
            step.duration_ms = (self._clock() - step._t0) * 1000
            self.steps.append(step)
            raise
        else:
            step.duration_ms = (self._clock() - step._t0) * 1000
            self.steps.append(step)

    def add(self, phase: str, action: str, **kwargs: Any) -> Step:
        """Record a zero-duration step (an observation rather than an action)."""
        step = Step(
            index=len(self.steps) + 1,
            phase=phase,
            action=action,
            input=kwargs.get("input"),
            output=kwargs.get("output"),
            evidence=dict(kwargs.get("evidence") or {}),
            status=kwargs.get("status", "ok"),
            started_at=_iso_now(),
        )
        self.steps.append(step)
        return step

    def note(self, text: str) -> None:
        self.notes.append(text)

    # -- verdict -----------------------------------------------------------

    @staticmethod
    def build_verdict(
        *,
        egress: Mapping[str, Any],
        filesystem: Mapping[str, Any],
        snapshot_diff: Mapping[str, Any] | None,
        chain: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compute pass/fail from observable evidence only."""
        checks: list[dict[str, Any]] = []

        blocked = int(egress.get("blocked_count", 0))
        attempts = egress.get("attempts", [])
        non_loopback_allowed = [
            a for a in attempts if a.get("allowed") and a.get("reason") != "loopback"
        ]
        checks.append(
            {
                "name": "no_egress",
                "passed": blocked == 0 and not non_loopback_allowed,
                "detail": (
                    f"{len(attempts)} socket event(s), {blocked} blocked, "
                    f"{len(non_loopback_allowed)} non-loopback connection(s) allowed"
                ),
            }
        )

        root = str(filesystem.get("root", ""))
        writes = filesystem.get("writes", [])
        escapes = [w for w in writes if root and not _is_under(str(w.get("path", "")), root)]
        checks.append(
            {
                "name": "sandbox_writes_only",
                "passed": not escapes and bool(filesystem.get("enforced", False)),
                "detail": (
                    f"{len(writes)} write(s), {len(escapes)} outside {root}"
                    if root
                    else "no sandbox root recorded"
                ),
            }
        )

        if snapshot_diff is None:
            checks.append(
                {
                    "name": "real_config_untouched",
                    "passed": True,
                    "detail": "no real config directory was inspected in this run",
                    "skipped": True,
                }
            )
        else:
            checks.append(
                {
                    "name": "real_config_untouched",
                    "passed": bool(snapshot_diff.get("identical")),
                    "detail": (
                        f"{snapshot_diff.get('file_count', 0)} file(s) hashed before and "
                        f"after; added={len(snapshot_diff.get('added', []))} "
                        f"removed={len(snapshot_diff.get('removed', []))} "
                        f"changed={len(snapshot_diff.get('changed', []))}"
                    ),
                }
            )

        if chain is not None:
            checks.append(
                {
                    "name": "chain_verifies",
                    "passed": bool(chain.get("ok")),
                    "detail": str(chain.get("detail", "")),
                }
            )

        denied_hits = [
            a
            for a in attempts
            if a.get("kind") in ("resolve", "connect")
            and "public CA" in str(a.get("reason", ""))
        ]
        checks.append(
            {
                "name": "no_public_ca_contact",
                "passed": not denied_hits,
                "detail": f"{len(denied_hits)} attempt(s) against public CA hostnames",
            }
        )

        return {
            "passed": all(c["passed"] for c in checks),
            "checks": checks,
        }

    def finish(
        self,
        *,
        egress: Mapping[str, Any],
        filesystem: Mapping[str, Any],
        snapshot_diff: Mapping[str, Any] | None = None,
        chain: Mapping[str, Any] | None = None,
        result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.containment = {
            "egress": dict(egress),
            "filesystem": dict(filesystem),
            "real_config_snapshot": dict(snapshot_diff) if snapshot_diff else None,
        }
        if result:
            self.result = dict(result)
        return self.to_dict(chain=chain)

    def to_dict(self, *, chain: Mapping[str, Any] | None = None) -> dict[str, Any]:
        duration_ms = (self._clock() - self._t0) * 1000
        verdict = self.build_verdict(
            egress=self.containment.get("egress", {}),
            filesystem=self.containment.get("filesystem", {}),
            snapshot_diff=self.containment.get("real_config_snapshot"),
            chain=chain,
        )
        return {
            "schema": SCHEMA_VERSION,
            "scenario": self.scenario,
            "started_at": self.started_at,
            "finished_at": _iso_now(),
            "duration_ms": round(duration_ms, 3),
            "inputs": _truncate(self.inputs),
            "steps": [s.to_dict() for s in self.steps],
            "containment": _truncate(self.containment),
            "result": _truncate(self.result),
            "notes": list(self.notes),
            "verdict": verdict,
        }

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        return path


def _is_under(path: str, root: str) -> bool:
    try:
        return Path(path).resolve().is_relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False
