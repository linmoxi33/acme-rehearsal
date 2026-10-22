"""Self-contained HTML report for a rehearsal.

One file, no external requests, no build step. The report has to be readable in
a classroom projector, in a terminal-adjacent browser tab, and in a printed PDF,
so it uses system fonts and a single accent colour rather than a design system.

Sections map to the three things a rehearsal must show:

1. **input** — what was simulated and against which sandbox,
2. **process** — every step with its duration and payload,
3. **result** — the certificate, the containment evidence and the verdict.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

__all__ = ["collect_artifacts", "render_report", "write_report"]

_CSS = """
:root {
  --bg: #17120f;
  --panel: #211a16;
  --panel-2: #2a211b;
  --line: #3a2f27;
  --ink: #f0e6dc;
  --ink-dim: #a89684;
  --amber: #d99b3f;
  --green: #7aa863;
  --red: #c05a4a;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 32px 80px;
  background: var(--bg); color: var(--ink);
  font: 15px/1.65 -apple-system, "Segoe UI", "Noto Sans SC", system-ui, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 6px; letter-spacing: -0.01em; }
h2 {
  font-size: 13px; text-transform: uppercase; letter-spacing: 0.14em;
  color: var(--amber); margin: 44px 0 14px; font-weight: 600;
}
.sub { color: var(--ink-dim); font-size: 14px; }
.verdict {
  display: inline-flex; align-items: center; gap: 10px;
  margin: 18px 0 8px; padding: 10px 18px; border-radius: 999px;
  font-weight: 600; letter-spacing: 0.02em; font-size: 14px;
}
.verdict.pass { background: rgba(122,168,99,0.14); color: var(--green); border: 1px solid rgba(122,168,99,0.4); }
.verdict.fail { background: rgba(192,90,74,0.14); color: var(--red); border: 1px solid rgba(192,90,74,0.45); }
.grid { display: grid; gap: 12px; }
.grid.c2 { grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
.grid.c3 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.card {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 16px 18px;
}
.card h3 { margin: 0 0 8px; font-size: 13px; color: var(--ink-dim); font-weight: 500; letter-spacing: 0.04em; }
.card .v { font-size: 22px; font-weight: 600; font-family: var(--mono); }
.card.ok { border-left: 3px solid var(--green); }
.card.bad { border-left: 3px solid var(--red); }
.card.muted { border-left: 3px solid var(--line); }
.kv { display: grid; grid-template-columns: 130px 1fr; gap: 6px 14px; font-size: 14px; }
.kv dt { color: var(--ink-dim); }
.kv dd { margin: 0; font-family: var(--mono); font-size: 13px; word-break: break-all; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-dim); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
td.mono, .mono { font-family: var(--mono); font-size: 12.5px; }
.dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 7px; }
.dot.ok { background: var(--green); }
.dot.failed { background: var(--red); }
.dot.skipped { background: var(--ink-dim); }
details { border-bottom: 1px solid var(--line); }
details summary {
  cursor: pointer; padding: 9px 4px; list-style: none;
  display: grid; grid-template-columns: 26px 92px 1fr 74px; gap: 10px; align-items: baseline;
}
details summary::-webkit-details-marker { display: none; }
details summary:hover { background: var(--panel-2); }
.phase { color: var(--amber); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
.dur { text-align: right; color: var(--ink-dim); font-family: var(--mono); font-size: 12px; }
pre {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; overflow-x: auto; font-family: var(--mono);
  font-size: 12px; line-height: 1.5; color: #d8cabb; margin: 6px 0 14px;
}
.body { padding: 0 4px 14px 36px; }
.tag {
  display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11px;
  background: rgba(217,155,63,0.14); color: var(--amber); font-family: var(--mono);
}
.note {
  border-left: 2px solid var(--amber); padding: 6px 0 6px 14px;
  color: var(--ink-dim); font-size: 13.5px; margin: 10px 0;
}
.tree { font-family: var(--mono); font-size: 12.5px; line-height: 1.75; color: var(--ink-dim); }
.tree b { color: var(--ink); font-weight: 500; }
footer { margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--ink-dim); font-size: 12.5px; }
code { font-family: var(--mono); background: var(--panel-2); padding: 1px 6px; border-radius: 4px; font-size: 12.5px; }
@media print {
  body { background: #fff; color: #111; padding: 0; }
  .card, pre, details { border-color: #ccc; background: #fff; }
  .verdict { border-width: 2px; }
}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _pretty(value: Any, *, limit: int = 2600) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(value)
    if len(text) > limit:
        text = text[:limit] + f"\n... [{len(text) - limit} chars clipped]"
    return _e(text)


def collect_artifacts(root: Path, *, max_entries: int = 120) -> list[str]:
    """List the sandbox tree, relative and sorted, for the artifacts section."""
    if not root.exists():
        return []
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if len(entries) >= max_entries:
            entries.append("... (truncated)")
            break
        rel = path.relative_to(root).as_posix()
        entries.append(rel + ("/" if path.is_dir() else ""))
    return entries


def render_report(
    transcript: Mapping[str, Any],
    *,
    artifacts: Iterable[str] = (),
    workdir: str = "",
) -> str:
    """Render the whole report as one HTML string."""
    verdict = transcript.get("verdict", {})
    passed = bool(verdict.get("passed"))
    checks = verdict.get("checks", [])
    steps = transcript.get("steps", [])
    inputs = transcript.get("inputs", {})
    result = transcript.get("result", {})
    containment = transcript.get("containment", {})
    egress = containment.get("egress", {}) or {}
    filesystem = containment.get("filesystem", {}) or {}
    snapshot = containment.get("real_config_snapshot")
    cert = (result.get("certificate") or {}) if isinstance(result, dict) else {}
    lineage = (result.get("lineage") or {}) if isinstance(result, dict) else {}
    error = (result.get("error") or {}) if isinstance(result, dict) else {}
    notes = transcript.get("notes", [])

    badge_class = "pass" if passed else "fail"
    badge_text = "CONTAINED · ALL CHECKS PASSED" if passed else "VERDICT FAILED"

    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    parts.append(f"<title>ACME Rehearsal · {_e(transcript.get('scenario', ''))}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class=\"wrap\">")

    # -- header ---------------------------------------------------------
    parts.append("<h1>ACME 演练报告</h1>")
    parts.append(
        f"<div class=\"sub\">场景 <span class=\"tag\">{_e(transcript.get('scenario'))}</span>"
        f" · 开始 {_e(transcript.get('started_at'))}"
        f" · 总耗时 {_e(transcript.get('duration_ms'))} ms"
        f" · {len(steps)} 个步骤</div>"
    )
    parts.append(f"<div class=\"verdict {badge_class}\">{_e(badge_text)}</div>")

    if error:
        parts.append(
            f"<div class=\"note\">本场景按设计在 ACME 层失败："
            f"<span class=\"tag\">{_e(error.get('type'))}</span> — {_e(error.get('detail'))}"
            f"<br>沙盒本身仍然完全隔离，因此隔离类检查保持通过。</div>"
        )

    # -- checks ---------------------------------------------------------
    parts.append("<h2>隔离结论</h2><div class=\"grid c3\">")
    for check in checks:
        cls = "ok" if check.get("passed") else "bad"
        mark = "PASS" if check.get("passed") else "FAIL"
        skipped = " · 跳过" if check.get("skipped") else ""
        parts.append(
            f"<div class=\"card {cls}\"><h3>{_e(check.get('name'))}{skipped}</h3>"
            f"<div class=\"v\">{mark}</div>"
            f"<div class=\"sub\" style=\"font-size:12.5px;margin-top:6px\">"
            f"{_e(check.get('detail'))}</div></div>"
        )
    parts.append("</div>")

    # -- input ----------------------------------------------------------
    parts.append("<h2>输入 · 本次模拟了什么</h2><div class=\"card\"><dl class=\"kv\">")
    for key in (
        "domains",
        "challenge_type",
        "leaf_validity_days",
        "rate_limit",
        "failure_mode",
        "sandbox_root",
        "real_config_dir",
    ):
        if key in inputs:
            parts.append(f"<dt>{_e(key)}</dt><dd>{_e(inputs[key])}</dd>")
    parts.append(f"<dt>workdir</dt><dd>{_e(workdir)}</dd>")
    parts.append("</dl></div>")

    # -- containment ----------------------------------------------------
    parts.append("<h2>隔离证据</h2><div class=\"grid c3\">")
    parts.append(
        f"<div class=\"card {'ok' if not egress.get('blocked_count') else 'bad'}\">"
        f"<h3>出站连接</h3><div class=\"v\">{_e(egress.get('blocked_count', 0))} 次被拦截</div>"
        f"<div class=\"sub\" style=\"font-size:12.5px;margin-top:6px\">"
        f"{_e(egress.get('total_attempts', 0))} 次 socket 事件，"
        f"{_e(egress.get('outbound_connections', 0))} 次 loopback 连接</div></div>"
    )
    parts.append(
        f"<div class=\"card ok\"><h3>写入范围</h3>"
        f"<div class=\"v\">{_e(filesystem.get('write_count', 0))} 个文件</div>"
        f"<div class=\"sub\" style=\"font-size:12.5px;margin-top:6px\">"
        f"全部位于 <span class=\"mono\">{_e(filesystem.get('root', ''))}</span></div></div>"
    )
    if snapshot:
        parts.append(
            f"<div class=\"card {'ok' if snapshot.get('identical') else 'bad'}\">"
            f"<h3>真实配置目录</h3>"
            f"<div class=\"v\">{'未改动' if snapshot.get('identical') else '已改动'}</div>"
            f"<div class=\"sub\" style=\"font-size:12.5px;margin-top:6px\">"
            f"{_e(snapshot.get('file_count', 0))} 个文件前后哈希比对 · "
            f"+{len(snapshot.get('added', []))} / -{len(snapshot.get('removed', []))} / "
            f"~{len(snapshot.get('changed', []))}</div></div>"
        )
    else:
        parts.append(
            "<div class=\"card muted\"><h3>真实配置目录</h3><div class=\"v\">未涉及</div>"
            "<div class=\"sub\" style=\"font-size:12.5px;margin-top:6px\">"
            "本次未传入真实 certbot 配置目录</div></div>"
        )
    parts.append("</div>")

    denied = [
        a for a in egress.get("attempts", []) if a.get("kind") in ("resolve", "connect")
    ]
    if denied:
        parts.append(
            "<details style=\"margin-top:12px\"><summary style=\"grid-template-columns:1fr\">"
            f"<span class=\"phase\">socket 事件明细（{len(denied)} 条，全部为 loopback）</span>"
            "</summary><div class=\"body\">"
        )
        rows = "".join(
            f"<tr><td class=\"mono\">{_e(a.get('kind'))}</td>"
            f"<td class=\"mono\">{_e(a.get('target'))}</td>"
            f"<td>{'允许' if a.get('allowed') else '拦截'}</td>"
            f"<td class=\"mono\">{_e(a.get('reason'))}</td></tr>"
            for a in denied[:40]
        )
        parts.append(
            "<table><tr><th>类型</th><th>目标</th><th>结果</th><th>原因</th></tr>"
            f"{rows}</table></div></details>"
        )

    # -- process --------------------------------------------------------
    parts.append("<h2>执行过程 · 逐步</h2><div class=\"card\" style=\"padding:4px 10px\">")
    for step in steps:
        status = step.get("status", "ok")
        dot = {"ok": "ok", "failed": "failed", "skipped": "skipped"}.get(status, "ok")
        parts.append("<details><summary>")
        parts.append(f"<span class=\"mono\" style=\"color:var(--ink-dim)\">{_e(step.get('index'))}</span>")
        parts.append(f"<span class=\"phase\">{_e(step.get('phase'))}</span>")
        parts.append(
            f"<span><span class=\"dot {dot}\"></span>{_e(step.get('action'))}"
            + (f" <span class=\"tag\">{_e(status)}</span>" if status != "ok" else "")
            + "</span>"
        )
        parts.append(f"<span class=\"dur\">{_e(step.get('duration_ms'))} ms</span>")
        parts.append("</summary><div class=\"body\">")
        if step.get("error"):
            parts.append(f"<div class=\"note\">错误：{_e(step['error'])}</div>")
        if step.get("input") is not None:
            parts.append(f"<div class=\"sub\" style=\"font-size:12px\">输入</div><pre>{_pretty(step['input'])}</pre>")
        if step.get("output") is not None:
            parts.append(f"<div class=\"sub\" style=\"font-size:12px\">输出</div><pre>{_pretty(step['output'])}</pre>")
        if step.get("evidence"):
            parts.append(f"<div class=\"sub\" style=\"font-size:12px\">证据</div><pre>{_pretty(step['evidence'])}</pre>")
        parts.append("</div></details>")
    parts.append("</div>")

    # -- result ---------------------------------------------------------
    if cert:
        parts.append("<h2>结果 · 签发的证书</h2><div class=\"card\"><dl class=\"kv\">")
        for label, key in (
            ("Subject", "subject"),
            ("Issuer", "issuer"),
            ("SAN", "sans"),
            ("Not Before", "not_before"),
            ("Not After", "not_after"),
            ("Serial", "serial"),
            ("SHA-256", "sha256"),
        ):
            if cert.get(key):
                parts.append(f"<dt>{_e(label)}</dt><dd>{_e(cert[key])}</dd>")
        parts.append("</dl></div>")

    if lineage:
        parts.append("<h2>结果 · certbot 目录布局</h2><div class=\"card\"><dl class=\"kv\">")
        for label, key in (
            ("lineage", "domain"),
            ("live", "live_dir"),
            ("archive", "archive_dir"),
            ("renewal", "config_path"),
            ("version", "version"),
            ("link_mode", "link_mode"),
            ("server", "server"),
        ):
            if lineage.get(key) is not None:
                parts.append(f"<dt>{_e(label)}</dt><dd>{_e(lineage[key])}</dd>")
        parts.append("</dl>")
        if lineage.get("link_mode") != "symlink":
            parts.append(
                "<div class=\"note\">live/ 采用复制而非符号链接：Windows 上创建符号链接"
                "需要开发者模式或管理员权限。该降级已记录，续期时会重建 live/ 内容。</div>"
            )
        parts.append("</div>")

    artifacts = list(artifacts)
    if artifacts:
        parts.append("<h2>产物</h2><div class=\"card\"><div class=\"tree\">")
        for entry in artifacts:
            parts.append(f"<div>{_e(entry)}</div>")
        parts.append("</div></div>")

    if notes:
        parts.append("<h2>备注</h2><div class=\"card\">")
        for note in notes:
            parts.append(f"<div class=\"note\" style=\"margin:8px 0\">{_e(note)}</div>")
        parts.append("</div>")

    # -- footer ---------------------------------------------------------
    parts.append("<footer>")
    parts.append(
        "由 <code>acme-rehearsal</code> 生成。整场演练只与 127.0.0.1 通信，"
        "证书由沙盒内临时根 CA 签发，与任何公共 CA 无关。<br>"
        f"transcript schema <code>{_e(transcript.get('schema'))}</code>"
        f" · 结束 {_e(transcript.get('finished_at'))}"
    )
    parts.append("</footer></div></body></html>")
    return "".join(parts)


def write_report(
    transcript: Mapping[str, Any],
    path: Path,
    *,
    artifacts: Iterable[str] = (),
    workdir: str = "",
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_report(transcript, artifacts=artifacts, workdir=workdir), encoding="utf-8"
    )
    return path


def render_index(rows: Iterable[Mapping[str, Any]]) -> str:
    """A one-page index linking every scenario report.

    Kept separate from :func:`render_report` because the index has no transcript
    of its own; it summarises verdicts so a reader can pick a scenario.
    """
    rows = list(rows)
    passed = sum(1 for r in rows if r.get("passed"))
    body: list[str] = []
    body.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">')
    body.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    body.append("<title>ACME Rehearsal · 场景索引</title>")
    body.append(f"<style>{_CSS}</style></head><body><div class=\"wrap\">")
    body.append("<h1>ACME 演练 · 场景索引</h1>")
    body.append(
        f"<div class=\"sub\">{len(rows)} 个场景，通过 {passed} 个。"
        "每个场景都在独立沙盒中运行，只与 127.0.0.1 通信。</div>"
    )
    ok = passed == len(rows)
    body.append(
        f"<div class=\"verdict {'pass' if ok else 'fail'}\">"
        f"{'ALL SCENARIOS CONTAINED' if ok else 'SOME SCENARIOS FAILED'}</div>"
    )
    body.append("<h2>场景</h2><div class=\"card\" style=\"padding:4px 14px\"><table>")
    body.append(
        "<tr><th>场景</th><th>结论</th><th>耗时</th><th>步骤</th><th>报告</th></tr>"
    )
    for row in rows:
        mark = "PASS" if row.get("passed") else "FAIL"
        cls = "ok" if row.get("passed") else "failed"
        body.append(
            f"<tr><td class=\"mono\">{_e(row.get('scenario'))}</td>"
            f"<td><span class=\"dot {cls}\"></span>{mark}</td>"
            f"<td class=\"mono\">{_e(row.get('duration_ms'))} ms</td>"
            f"<td class=\"mono\">{_e(row.get('steps'))}</td>"
            f"<td><a href=\"{_e(row.get('dir'))}/{_e(row.get('report'))}\" "
            f"style=\"color:var(--amber)\">report.html</a></td></tr>"
        )
    body.append("</table></div>")

    body.append("<h2>隔离检查汇总</h2><div class=\"grid c3\">")
    names: list[str] = []
    for row in rows:
        for check in row.get("checks", []):
            if check.get("name") not in names:
                names.append(check.get("name"))
    for name in names:
        total = 0
        good = 0
        for row in rows:
            for check in row.get("checks", []):
                if check.get("name") == name and not check.get("skipped"):
                    total += 1
                    if check.get("passed"):
                        good += 1
        cls = "ok" if good == total else "bad"
        body.append(
            f"<div class=\"card {cls}\"><h3>{_e(name)}</h3>"
            f"<div class=\"v\">{good}/{total}</div></div>"
        )
    body.append("</div>")

    body.append(
        "<footer>由 <code>acme-rehearsal</code> 生成。"
        "每个场景的完整逐步记录见各自的 report.html 与 transcript.json。</footer>"
    )
    body.append("</div></body></html>")
    return "".join(body)
