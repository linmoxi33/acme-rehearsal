"""Assert a built wheel contains everything needed to run.

Checks that would have caught real packaging mistakes:

* a module silently dropped from the package (``setuptools`` discovery misconfigured
  so a new file is not included),
* the licence text missing from the distribution,
* the console-script entry point missing, which makes ``acme-rehearsal`` install
  successfully but not exist on PATH.

Exit code 1 on any failure so it can gate CI.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

REQUIRED_MODULES = {
    "__init__.py",
    "__main__.py",
    "ca.py",
    "challenges.py",
    "cli.py",
    "client.py",
    "guard.py",
    "preview.py",
    "protocol.py",
    "rehearsal.py",
    "report.py",
    "server.py",
    "store.py",
    "transcript.py",
}


def check(wheel_path: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        modules = {
            Path(name).name
            for name in names
            if name.startswith("acme_rehearsal/") and name.endswith(".py")
        }
        entry_points = [n for n in names if n.endswith("entry_points.txt")]

        missing = REQUIRED_MODULES - modules
        if missing:
            problems.append(f"missing modules: {sorted(missing)}")

        if not any("LICENSE" in name for name in names):
            problems.append("LICENSE not included in the wheel")

        if not entry_points:
            problems.append("entry_points.txt missing; console script will not install")
        else:
            content = archive.read(entry_points[0]).decode()
            if "acme-rehearsal" not in content:
                problems.append(f"console script not declared: {content!r}")

        unexpected = modules - REQUIRED_MODULES
        if unexpected:
            # Not fatal: a new module legitimately appears here. Reported so the
            # required list gets updated rather than silently drifting.
            print(f"note: modules not in the required list: {sorted(unexpected)}")

        print(f"wheel: {wheel_path.name}")
        print(f"  entries        {len(names)}")
        print(f"  modules        {len(modules)}")
        print(f"  entry points   {len(entry_points)}")

    return problems


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        wheel = Path(argv[1])
    else:
        candidates = sorted(Path("dist").glob("*.whl"))
        if not candidates:
            print("no wheel found in dist/; build first", file=sys.stderr)
            return 1
        wheel = candidates[-1]

    problems = check(wheel)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
