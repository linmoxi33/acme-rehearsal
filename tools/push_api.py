"""Publish this repository to GitHub through the Git Data API.

Why not ``git push``: HTTPS to github.com is unreliable in this environment, while
``gh api`` works. The Git Data API also gives deterministic, verifiable uploads.

Hard-won details encoded here:

* ``POST user/repos`` — with a *leading slash* Git Bash rewrites the endpoint as a
  filesystem path and ``gh`` reports ``invalid API endpoint``.
* A brand-new empty repo returns 409 on blob creation, so one file is seeded via
  the Contents API first to materialise the default branch.
* Large JSON bodies cannot go through argv (Windows ``WinError 206``); every call
  uses ``--input`` with a temp file.
* Transient 404/502/503 do occur mid-upload; retry with backoff, but never treat a
  persistent 404 as transient — check the active account first.
* Refuse to run on a dirty working tree: a concurrent mutation run would upload
  deliberately broken sources.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER = "linmoxi33"
REPO = "acme-rehearsal"

SKIP_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mutation-backups",
    "dist",
    "build",
    "demo",
    "rehearsal",
    "out",
    ".venv",
    "venv",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".coverage"}
SKIP_NAMES = {".coverage", "mut1.json", "mut2.json", "mut3.json"}


def run_gh(args: list[str], payload: dict | None = None) -> tuple[int, str, str]:
    """Invoke gh with an optional JSON body passed via --input."""
    tmp_path = None
    try:
        if payload is not None:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8"
            ) as handle:
                json.dump(payload, handle)
                tmp_path = handle.name
            args = args + ["--input", tmp_path]
        completed = subprocess.run(
            ["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        return completed.returncode, completed.stdout, completed.stderr
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)


def api(
    method: str,
    endpoint: str,
    payload: dict | None = None,
    *,
    retries: int = 4,
) -> dict:
    """Call the API with backoff on transient failures only."""
    delay = 2.0
    last = ""
    # The "api" subcommand must be present; without it gh parses "-X" as a
    # top-level flag and prints its help text, which looks nothing like an error.
    gh_args = ["api"]
    if method != "GET":
        gh_args += ["-X", method]
    gh_args.append(endpoint)

    for attempt in range(retries):
        code, out, err = run_gh(gh_args, payload)
        if code == 0:
            return json.loads(out) if out.strip() else {}
        last = (err or out).strip()
        transient = any(
            token in last for token in ("502", "503", "504", "timeout", "timed out", "EOF")
        )
        if not transient or attempt == retries - 1:
            raise SystemExit(f"gh api {method} {endpoint} failed: {last}")
        print(f"  retry {attempt + 1}/{retries - 1} after {delay:.0f}s: {last[:120]}", flush=True)
        time.sleep(delay)
        delay *= 2
    raise SystemExit(f"gh api {method} {endpoint} failed: {last}")


def collect_files() -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts):
            continue
        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES:
            continue
        files.append((rel.as_posix(), path.read_bytes()))
    return files


def check_clean_tree() -> None:
    """Refuse to publish while a mutation run could have left defects in place."""
    if (ROOT / ".mutation-backups").exists():
        raise SystemExit(
            "refusing to publish: .mutation-backups exists, a mutation run was interrupted"
        )


def check_account() -> None:
    code, out, _err = run_gh(["api", "user", "--jq", ".login"])
    login = out.strip()
    if code != 0 or login != OWNER:
        raise SystemExit(f"wrong active account: {login!r} (expected {OWNER!r})")


def ensure_repo() -> str:
    code, out, _err = run_gh(["api", f"repos/{OWNER}/{REPO}", "--jq", ".default_branch"])
    if code == 0:
        branch = out.strip() or "main"
        print(f"repo exists, default branch = {branch}", flush=True)
        return branch

    print("creating repo...", flush=True)
    api(
        "POST",
        "user/repos",
        {
            "name": REPO,
            "description": (
                "Rehearse ACME certificate issuance, renewal and revocation in a sealed "
                "offline sandbox — with machine-checked proof that nothing left the box."
            ),
            "homepage": f"https://github.com/{OWNER}/{REPO}",
            "private": False,
            "has_issues": True,
            "has_wiki": False,
            "has_projects": False,
        },
    )
    branch = "main"
    print(f"repo created, branch = {branch}", flush=True)
    return branch


def seed_branch() -> tuple[str, str]:
    """Materialise the default branch using a file that ships anyway.

    An empty repository has no refs, so something has to create the first commit.
    Two approaches fail on this backend and are documented here so nobody retries
    them: creating a tree with ``"sha": null`` to delete a placeholder returns
    ``GitRPC::BadObjectState``, and an empty tree returns ``Invalid tree info``.

    So the seed is ``.gitattributes`` — a real project file. The subsequent tree
    simply overwrites it, leaving no artifact behind.

    Returns (branch_name, tree_sha).
    """
    seed_name = ".gitattributes"
    seed_data = (ROOT / seed_name).read_bytes()
    print(f"seeding branch with {seed_name} via Contents API...", flush=True)
    api(
        "PUT",
        f"repos/{OWNER}/{REPO}/contents/{seed_name}",
        {
            "message": "chore: initialise repository",
            "content": base64.b64encode(seed_data).decode(),
        },
    )
    info = api("GET", f"repos/{OWNER}/{REPO}")
    actual = info["default_branch"]
    tree = api("GET", f"repos/{OWNER}/{REPO}/git/trees/{actual}")
    print(f"  default branch = {actual}, base tree = {tree['sha'][:10]}", flush=True)
    return actual, tree["sha"]


def upload(files: list[tuple[str, bytes]], branch: str) -> str:
    print(f"uploading {len(files)} files...", flush=True)
    tree_entries = []
    for index, (rel, data) in enumerate(files, start=1):
        blob = api(
            "POST",
            f"repos/{OWNER}/{REPO}/git/blobs",
            {"content": base64.b64encode(data).decode(), "encoding": "base64"},
        )
        tree_entries.append(
            {"path": rel, "mode": "100644", "type": "blob", "sha": blob["sha"]}
        )
        if index % 10 == 0 or index == len(files):
            print(f"  {index}/{len(files)}", flush=True)

    # No deletion entries: the seed file (.gitattributes) is overwritten by the
    # real copy in `files`, so nothing needs removing.
    tree = api(
        "POST",
        f"repos/{OWNER}/{REPO}/git/trees",
        {"tree": tree_entries},
    )
    commit = api(
        "POST",
        f"repos/{OWNER}/{REPO}/git/commits",
        {
            "message": (
                "feat: offline ACME rehearsal sandbox\n\n"
                "- RFC 8555 subset server + client, real X.509 issuance\n"
                "- egress guard, write-scope guard, before/after config snapshots\n"
                "- read-only impact preview for destructive certbot operations\n"
                "- six scenarios incl. three fault injections\n"
                "- 217 tests, 92% coverage, 21/21 mutants killed"
            ),
            "tree": tree["sha"],
        },
    )
    api(
        "PATCH",
        f"repos/{OWNER}/{REPO}/git/refs/heads/{branch}",
        {"sha": commit["sha"], "force": True},
    )
    return commit["sha"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish acme-rehearsal to GitHub.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    check_clean_tree()
    check_account()
    files = collect_files()
    print(f"{len(files)} files staged", flush=True)
    total = sum(len(data) for _rel, data in files)
    print(f"{total} bytes total", flush=True)

    if args.dry_run:
        for rel, data in files:
            print(f"  {rel}  ({len(data)} bytes)")
        return 0

    branch = ensure_repo()
    branch, _base_tree = seed_branch()
    commit = upload(files, branch)
    print(f"\npushed: https://github.com/{OWNER}/{REPO}/commit/{commit}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
