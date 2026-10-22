"""Command line interface.

Output is deliberately plain: a rehearsal is something you run in a terminal and
then open in a browser. The CLI prints a compact summary and points at the two
artifacts (transcript + report) rather than dumping JSON at the user.

Exit codes: 0 when the verdict passed, 1 when it failed, 2 for usage errors
(argparse default). That makes the command usable as a CI gate.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .preview import Previewer
from .rehearsal import SCENARIOS, Rehearsal, RehearsalConfig
from .report import collect_artifacts, render_index, write_report

__all__ = ["main"]

_OPERATIONS = ("renew", "renew-force", "revoke", "delete", "expand")


def _configure_streams() -> None:
    """Force UTF-8 on stdout/stderr.

    Windows consoles default to a legacy code page; without this, any non-ASCII
    output raises UnicodeEncodeError and the rehearsal appears to crash after
    having actually succeeded.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acme-rehearsal",
        description=(
            "在完全离线的沙盒里排练 ACME 证书的签发、续期与吊销。"
            "所有网络流量限于 127.0.0.1，证书由沙盒内临时 CA 签发。"
        ),
    )
    parser.add_argument("--version", action="version", version=f"acme-rehearsal {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="运行一个演练场景")
    run.add_argument("--scenario", choices=SCENARIOS, default="issue")
    run.add_argument(
        "--domain",
        action="append",
        dest="domains",
        metavar="NAME",
        help="演练域名，可重复；默认 demo.example.test",
    )
    run.add_argument("--challenge", choices=("http-01", "dns-01"), default="http-01")
    run.add_argument("--workdir", type=Path, default=None, help="沙盒输出目录")
    run.add_argument("--validity-days", type=int, default=90, help="签发证书的有效期")
    run.add_argument("--rate-limit", type=int, default=0, help="每域名签发上限，0 表示不限制")
    run.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="真实 certbot 配置目录（只读；用于前后哈希比对证明未被改动）",
    )
    run.add_argument("--no-openssl", action="store_true", help="跳过 openssl 交叉验证")
    run.add_argument("--json", action="store_true", help="以 JSON 输出完整 transcript")
    run.add_argument("--quiet", action="store_true", help="只输出结论")

    preview = sub.add_parser("preview", help="只读预演高危操作的影响面")
    preview.add_argument("--config-dir", type=Path, required=True)
    preview.add_argument("--operation", choices=_OPERATIONS, default="renew")
    preview.add_argument(
        "--add-domain", action="append", dest="add_domains", default=[], metavar="NAME"
    )
    preview.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="复检一份已有 transcript 的结论")
    verify.add_argument("--transcript", type=Path, required=True)
    verify.add_argument("--json", action="store_true")

    demo = sub.add_parser("demo", help="依次运行全部场景并生成索引报告")
    demo.add_argument("--workdir", type=Path, default=None)
    demo.add_argument("--no-openssl", action="store_true")

    return parser


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    config = RehearsalConfig(
        domains=args.domains or ["demo.example.test"],
        challenge_type=args.challenge,
        workdir=args.workdir,
        leaf_validity_days=args.validity_days,
        rate_limit=args.rate_limit,
        real_config_dir=args.config_dir,
        run_openssl=not args.no_openssl,
    )
    rehearsal = Rehearsal(config)
    outcome = rehearsal.run(args.scenario)

    report_path = write_report(
        outcome.transcript,
        outcome.workdir / "report.html",
        artifacts=collect_artifacts(rehearsal.sandbox),
        workdir=str(outcome.workdir),
    )

    if args.json:
        print(json.dumps(outcome.transcript, indent=2, ensure_ascii=False))
    elif not args.quiet:
        _print_summary(outcome.transcript, outcome.workdir, report_path)
    else:
        print("PASSED" if outcome.passed else "FAILED")

    return 0 if outcome.passed else 1


def _cmd_preview(args: argparse.Namespace) -> int:
    previewer = Previewer(args.config_dir)
    scan = previewer.scan()

    if args.operation == "renew":
        operation = previewer.preview_renew()
    elif args.operation == "renew-force":
        operation = previewer.preview_renew(force=True)
    elif args.operation == "revoke":
        operation = previewer.preview_revoke()
    elif args.operation == "delete":
        operation = previewer.preview_delete()
    else:
        operation = previewer.preview_expand(args.add_domains)

    payload = {**scan.to_dict(), "preview": operation.to_dict()}
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"配置目录  {scan.config_dir}")
    print(f"lineage   {len(scan.lineages)} 个")
    for lineage in scan.lineages:
        days = lineage.get("days_remaining")
        print(
            f"  · {lineage['domain']:<28} 剩余 {days if days is not None else '?'} 天"
            f"  阈值 {lineage.get('renew_before_expiry')} 天"
            f"  链接 {lineage.get('link_mode')}"
        )
    print()
    print(f"操作      {operation.operation}  (风险: {operation.risk})")
    print(f"结论      {operation.summary}")
    for entry in operation.would_affect:
        extra = entry.get("reason") or entry.get("impact") or ""
        if "added_domains" in entry:
            added = entry["added_domains"] or []
            extra = f"新增 {', '.join(added)}" if added else "域名集合无变化"
        print(f"  → {entry.get('domain')}  {extra}".rstrip())
    for entry in operation.would_skip:
        print(f"  · {entry.get('domain')} 跳过 ({entry.get('reason', '')})")
    if operation.quota_estimate:
        print(f"配额      {operation.quota_estimate.get('certificates_requested', 0)} 张")
    if operation.files_touched:
        print(f"将触碰    {len(operation.files_touched)} 个路径")
        for path in operation.files_touched[:12]:
            print(f"  - {path}")
        if len(operation.files_touched) > 12:
            print(f"  ... 另有 {len(operation.files_touched) - 12} 个")
    for warning in scan.warnings + operation.warnings:
        print(f"  ! {warning}")
    print("\n本次预演为只读：未创建、修改或删除任何文件。")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    transcript = json.loads(args.transcript.read_text(encoding="utf-8"))
    verdict = transcript.get("verdict", {})
    if args.json:
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
    else:
        print(f"场景  {transcript.get('scenario')}")
        print(f"结论  {'PASSED' if verdict.get('passed') else 'FAILED'}")
        for check in verdict.get("checks", []):
            mark = "PASS" if check.get("passed") else "FAIL"
            skipped = " (skipped)" if check.get("skipped") else ""
            print(f"  [{mark}] {check.get('name')}{skipped}  {check.get('detail')}")
    return 0 if verdict.get("passed") else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    base = (args.workdir or Path("acme-rehearsal-demo")).resolve()
    base.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    failures = 0

    for scenario in SCENARIOS:
        workdir = base / scenario
        config = RehearsalConfig(
            domains=["demo.example.test"],
            workdir=workdir,
            run_openssl=not args.no_openssl,
        )
        rehearsal = Rehearsal(config)
        outcome = rehearsal.run(scenario)
        report = write_report(
            outcome.transcript,
            workdir / "report.html",
            artifacts=collect_artifacts(rehearsal.sandbox),
            workdir=str(workdir),
        )
        rows.append(
            {
                "scenario": scenario,
                "passed": outcome.passed,
                "duration_ms": outcome.transcript.get("duration_ms"),
                "steps": len(outcome.transcript.get("steps", [])),
                "report": report.name,
                "dir": workdir.name,
                "checks": outcome.transcript.get("verdict", {}).get("checks", []),
            }
        )
        if not outcome.passed:
            failures += 1
        print(
            f"{scenario:<22} {'PASS' if outcome.passed else 'FAIL':<5} "
            f"{outcome.transcript.get('duration_ms')} ms  -> {report}"
        )

    index = base / "index.html"
    index.write_text(render_index(rows), encoding="utf-8")
    print(f"\n索引  {index}")
    print(f"场景  {len(rows)} 个，失败 {failures} 个")
    return 0 if failures == 0 else 1


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _print_summary(transcript: dict[str, Any], workdir: Path, report_path: Path) -> None:
    verdict = transcript.get("verdict", {})
    passed = verdict.get("passed")
    print(f"场景    {transcript.get('scenario')}")
    print(f"结论    {'PASSED' if passed else 'FAILED'}")
    print(f"耗时    {transcript.get('duration_ms')} ms · {len(transcript.get('steps', []))} 步")
    print("检查")
    for check in verdict.get("checks", []):
        mark = "PASS" if check.get("passed") else "FAIL"
        skipped = " (跳过)" if check.get("skipped") else ""
        print(f"  [{mark}] {check.get('name'):<24}{skipped} {check.get('detail')}")

    result = transcript.get("result") or {}
    cert = result.get("certificate") or {}
    if cert:
        print("证书")
        print(f"  subject  {cert.get('subject')}")
        print(f"  issuer   {cert.get('issuer')}")
        print(f"  SAN      {', '.join(cert.get('sans', []))}")
        print(f"  expires  {cert.get('not_after')}")
    error = result.get("error") or {}
    if error:
        print(f"预期错误 {error.get('type')} — {error.get('detail')}")

    print(f"产物    {workdir}")
    print(f"报告    {report_path}")


def main(argv: Sequence[str] | None = None) -> int:
    _configure_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "run": _cmd_run,
        "preview": _cmd_preview,
        "verify": _cmd_verify,
        "demo": _cmd_demo,
    }
    handler = handlers[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
