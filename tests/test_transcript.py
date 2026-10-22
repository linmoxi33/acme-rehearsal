"""Transcript and verdict tests.

The verdict is the product's answer to "was this contained?". If it can only ever
return True, every other guarantee in the project is decorative. These tests
therefore feed it failing evidence and demand a failing verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

from acme_rehearsal.transcript import Recorder, Step, _truncate

_GOOD_EGRESS = {
    "blocked_count": 0,
    "attempts": [
        {"kind": "connect", "target": "127.0.0.1", "allowed": True, "reason": "loopback"}
    ],
}
_GOOD_FS = {"root": "/sandbox", "enforced": True, "writes": [{"path": "/sandbox/a", "bytes": 1}]}


def _verdict(egress=None, fs=None, snapshot=None, chain=None):
    return Recorder.build_verdict(
        egress=egress or _GOOD_EGRESS,
        filesystem=fs or _GOOD_FS,
        snapshot_diff=snapshot,
        chain=chain,
    )


def test_all_good_evidence_passes() -> None:
    verdict = _verdict()
    assert verdict["passed"] is True
    assert {c["name"] for c in verdict["checks"]} >= {
        "no_egress",
        "sandbox_writes_only",
        "no_public_ca_contact",
    }


def test_blocked_egress_fails_the_verdict() -> None:
    egress = {
        "blocked_count": 1,
        "attempts": [
            {"kind": "connect", "target": "1.2.3.4", "allowed": False, "reason": "non-loopback"}
        ],
    }
    verdict = _verdict(egress=egress)
    assert verdict["passed"] is False
    check = next(c for c in verdict["checks"] if c["name"] == "no_egress")
    assert check["passed"] is False


def test_non_loopback_connection_fails_even_without_blocks() -> None:
    """An allowed non-loopback connection is a leak even if nothing was blocked."""
    egress = {
        "blocked_count": 0,
        "attempts": [
            {"kind": "connect", "target": "example.com", "allowed": True, "reason": "explicitly allowed"}
        ],
    }
    verdict = _verdict(egress=egress)
    assert verdict["passed"] is False


def test_write_outside_root_fails_the_verdict() -> None:
    fs = {
        "root": "/sandbox",
        "enforced": True,
        "writes": [{"path": "/etc/passwd", "bytes": 1}],
    }
    verdict = _verdict(fs=fs)
    assert verdict["passed"] is False
    check = next(c for c in verdict["checks"] if c["name"] == "sandbox_writes_only")
    assert check["passed"] is False


def test_disabled_enforcement_fails_the_verdict() -> None:
    """Without enforcement the write-scope claim is unproven, so it cannot pass."""
    fs = {"root": "/sandbox", "enforced": False, "writes": []}
    verdict = _verdict(fs=fs)
    assert verdict["passed"] is False


def test_changed_real_config_fails_the_verdict() -> None:
    snapshot = {
        "identical": False,
        "file_count": 3,
        "added": ["new.conf"],
        "removed": [],
        "changed": [],
    }
    verdict = _verdict(snapshot=snapshot)
    assert verdict["passed"] is False
    check = next(c for c in verdict["checks"] if c["name"] == "real_config_untouched")
    assert check["passed"] is False


def test_identical_snapshot_passes() -> None:
    snapshot = {"identical": True, "file_count": 3, "added": [], "removed": [], "changed": []}
    assert _verdict(snapshot=snapshot)["passed"] is True


def test_missing_snapshot_is_marked_skipped_not_failed() -> None:
    verdict = _verdict(snapshot=None)
    check = next(c for c in verdict["checks"] if c["name"] == "real_config_untouched")
    assert check["passed"] is True
    assert check["skipped"] is True


def test_broken_chain_fails_the_verdict() -> None:
    verdict = _verdict(chain={"ok": False, "detail": "bad signature"})
    assert verdict["passed"] is False


def test_public_ca_attempt_fails_the_verdict() -> None:
    egress = {
        "blocked_count": 1,
        "attempts": [
            {
                "kind": "resolve",
                "target": "acme-v02.api.letsencrypt.org",
                "allowed": False,
                "reason": "public CA hostname denied pre-resolution",
            }
        ],
    }
    verdict = _verdict(egress=egress)
    check = next(c for c in verdict["checks"] if c["name"] == "no_public_ca_contact")
    assert check["passed"] is False


# --------------------------------------------------------------------------
# Recorder behaviour
# --------------------------------------------------------------------------


def test_step_records_duration_and_status() -> None:
    recorder = Recorder("issue")
    with recorder.step("acme", "new-order", input={"d": ["a.test"]}) as step:
        step.output = {"status": "pending"}
    assert len(recorder.steps) == 1
    recorded = recorder.steps[0]
    assert recorded.status == "ok"
    assert recorded.duration_ms >= 0
    assert recorded.index == 1


def test_failing_step_is_recorded_then_reraised() -> None:
    recorder = Recorder("issue")
    try:
        with recorder.step("acme", "finalize"):
            raise ValueError("boom")
    except ValueError:
        pass
    assert len(recorder.steps) == 1
    assert recorder.steps[0].status == "failed"
    assert "boom" in recorder.steps[0].error


def test_step_indices_are_contiguous_after_a_failure() -> None:
    recorder = Recorder("issue")
    recorder.add("setup", "one")
    try:
        with recorder.step("acme", "two"):
            raise RuntimeError("x")
    except RuntimeError:
        pass
    recorder.add("acme", "three")
    assert [s.index for s in recorder.steps] == [1, 2, 3]


def test_notes_and_inputs_survive_serialisation() -> None:
    recorder = Recorder("issue")
    recorder.inputs = {"domains": ["a.test"]}
    recorder.note("a remark")
    recorder.add("setup", "start")
    payload = recorder.finish(egress=_GOOD_EGRESS, filesystem=_GOOD_FS)
    assert payload["inputs"]["domains"] == ["a.test"]
    assert payload["notes"] == ["a remark"]
    assert payload["schema"] == "acme-rehearsal/1"


def test_transcript_json_roundtrip(tmp_path: Path) -> None:
    recorder = Recorder("issue")
    recorder.add("setup", "start", output={"a": 1})
    recorder.finish(egress=_GOOD_EGRESS, filesystem=_GOOD_FS)
    path = recorder.write_json(tmp_path / "t.json")
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded["steps"][0]["action"] == "start"


def test_truncate_clips_long_strings() -> None:
    clipped = _truncate("x" * 5000)
    assert "chars clipped" in clipped
    assert len(clipped) < 5000


def test_truncate_recurses_into_containers() -> None:
    payload = {"a": ["y" * 5000], "b": {"c": "z" * 5000}}
    clipped = _truncate(payload)
    assert "chars clipped" in clipped["a"][0]
    assert "chars clipped" in clipped["b"]["c"]


def test_truncate_leaves_short_values_alone() -> None:
    assert _truncate({"a": 1, "b": "short"}) == {"a": 1, "b": "short"}


def test_step_to_dict_omits_empty_fields() -> None:
    step = Step(index=1, phase="p", action="a")
    payload = step.to_dict()
    assert "input" not in payload
    assert "error" not in payload
