"""Upload a single file through the Contents API.

Used when one file was created after the bulk push and a full re-push would add
an unnecessary commit.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

OWNER = "linmoxi33"
REPO = "acme-rehearsal"
ROOT = Path(__file__).resolve().parents[1]


def upload(rel_path: str, message: str) -> None:
    local = ROOT / rel_path
    payload = {
        "message": message,
        "content": base64.b64encode(local.read_bytes()).decode(),
        "branch": "main",
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(payload, fh)
        tmp = fh.name
    try:
        completed = subprocess.run(
            [
                "gh",
                "api",
                "-X",
                "PUT",
                f"repos/{OWNER}/{REPO}/contents/{rel_path}",
                "--input",
                tmp,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        Path(tmp).unlink(missing_ok=True)

    if completed.returncode != 0:
        raise SystemExit(f"upload failed: {completed.stderr.strip()}")
    result = json.loads(completed.stdout)
    print(f"uploaded {rel_path} -> {result['commit']['sha'][:10]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: put_one.py <repo-relative-path> [message]")
    upload(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else f"chore: add {sys.argv[1]}")
