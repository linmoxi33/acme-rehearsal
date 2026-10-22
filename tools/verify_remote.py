"""Verify every remote blob byte-for-byte against the working tree.

Blob hashes are not a reliable comparison on their own: a repository with
``* text=auto eol=lf`` normalises line endings on checkout, so a local file may
differ from its blob while the hash matches. This downloads each blob's raw
content and compares bytes.

A mismatch that disappears under CRLF normalisation is reported separately as
"line-endings-only" rather than silently counted as a pass — that distinction is
what tells you whether the content is correct but the checkout policy differs, or
whether the uploads are actually different files.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER = "linmoxi33"
REPO = "acme-rehearsal"


def gh(*args: str) -> str:
    """Invoke the GitHub API. The ``api`` subcommand is mandatory — omitting it
    makes gh treat the endpoint as a subcommand name and print its help instead of
    failing, which reads like an empty result."""
    completed = subprocess.run(
        ["gh", "api", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise SystemExit(f"gh {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout


def main() -> int:
    ref = json.loads(gh(f"repos/{OWNER}/{REPO}/git/ref/heads/main"))
    tree_sha = ref["object"]["sha"]
    commit = json.loads(gh(f"repos/{OWNER}/{REPO}/git/commits/{tree_sha}"))
    root_tree = commit["tree"]["sha"]

    listing = json.loads(
        gh(f"repos/{OWNER}/{REPO}/git/trees/{root_tree}?recursive=1")
    )
    blobs = [entry for entry in listing["tree"] if entry["type"] == "blob"]
    print(f"remote commit {tree_sha[:10]} -> {len(blobs)} blobs")
    if not blobs:
        print("FAIL: no blobs found; the traversal is meaningless")
        return 1

    local_files = sorted(
        p.relative_to(ROOT).as_posix()
        for p in ROOT.rglob("*")
        if p.is_file()
        and not any(
            part in {"__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build", ".mutation-backups"}
            or part.endswith(".egg-info")
            for part in p.relative_to(ROOT).parts
        )
        and p.suffix not in {".pyc", ".pyo"}
        and p.name != ".coverage"
    )

    remote_paths = {entry["path"] for entry in blobs}
    local_set = set(local_files)

    only_remote = sorted(remote_paths - local_set)
    only_local = sorted(local_set - remote_paths)

    mismatched: list[str] = []
    eol_only: list[str] = []
    identical = 0

    for entry in blobs:
        path = entry["path"]
        local_path = ROOT / path
        if not local_path.exists():
            continue
        payload = json.loads(
            gh(f"repos/{OWNER}/{REPO}/git/blobs/{entry['sha']}")
        )
        remote_bytes = base64.b64decode(payload["content"])
        local_bytes = local_path.read_bytes()
        if remote_bytes == local_bytes:
            identical += 1
            continue
        normalised_remote = remote_bytes.replace(b"\r\n", b"\n")
        normalised_local = local_bytes.replace(b"\r\n", b"\n")
        if normalised_remote == normalised_local:
            eol_only.append(path)
        else:
            mismatched.append(path)

    print(f"identical            {identical}")
    print(f"line-endings-only    {len(eol_only)}")
    print(f"mismatched           {len(mismatched)}")
    if only_remote:
        print(f"only on remote  ({len(only_remote)}): {only_remote}")
    if only_local:
        print(f"only locally    ({len(only_local)}): {only_local}")
    if mismatched:
        print("\nbyte mismatches:")
        for path in mismatched:
            print(f"  - {path}")
    if eol_only:
        print("\nline-ending differences (content equal after normalisation):")
        for path in eol_only:
            print(f"  - {path}")

    ok = not mismatched and not only_remote and not only_local
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
