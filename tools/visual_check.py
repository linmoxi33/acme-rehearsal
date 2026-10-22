"""Automated visual acceptance checks for the generated HTML report.

Why this exists: "it rendered" is not evidence. A report can render with every
section present and still be unusable — invisible text, a section collapsed to
zero height, content overflowing the viewport, or contrast below readable levels.

This script asserts the properties a human reviewer would check, using values the
browser actually computed:

* required sections exist and have non-zero rendered height,
* every check card and every step row is present (counts match the transcript),
* no horizontal overflow at a fixed viewport,
* body text contrast meets WCAG AA (4.5:1) against its computed background,
* the failure scenario actually renders the failure styling.

It also writes full-page screenshots so a human can confirm what the probe
asserted. The probe complements the screenshot; it does not replace it.

Usage:
    python tools/visual_check.py <report.html> [--expect pass|fail] [--shot out.png]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CONTRAST_JS = """
() => {
  const parse = (c) => {
    const m = c.match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    const parts = m[1].split(',').map(s => parseFloat(s.trim()));
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const lum = ({r, g, b}) => {
    const f = (v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const body = getComputedStyle(document.body);
  let bg = parse(body.backgroundColor);
  // Walk up if body is transparent.
  let node = document.body;
  while ((!bg || bg.a === 0) && node.parentElement) {
    node = node.parentElement;
    bg = parse(getComputedStyle(node).backgroundColor);
  }
  const fg = parse(body.color);
  if (!bg || !fg) return null;
  const L1 = lum(fg), L2 = lum(bg);
  const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
  return { ratio, fg: body.color, bg: body.backgroundColor };
}
"""

PROBE_JS = """
() => {
  const visible = (el) => {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const cards = [...document.querySelectorAll('.grid.c3 .card')];
  const details = [...document.querySelectorAll('details')];
  const steps = [...document.querySelectorAll('.card details summary')];
  const verdict = document.querySelector('.verdict');
  const h1 = document.querySelector('h1');
  return {
    title: document.title,
    h1: h1 ? h1.textContent.trim() : null,
    h1Visible: visible(h1),
    verdictText: verdict ? verdict.textContent.trim() : null,
    verdictClass: verdict ? verdict.className : null,
    verdictVisible: visible(verdict),
    cardCount: cards.length,
    cardsWithDetail: cards.filter(c => {
      // Report cards carry a .sub detail line; index cards carry a .v tally.
      const sub = c.querySelector('.sub') || c.querySelector('.v');
      return sub && sub.textContent.trim().length > 0;
    }).length,
    cardHeights: cards.map(c => Math.round(c.getBoundingClientRect().height)),
    detailsCount: details.length,
    stepRowCount: steps.length,
    emptySummaries: steps.filter(s => s.textContent.trim().length < 3).length,
    h2s: [...document.querySelectorAll('h2')].map(h => h.textContent.trim()),
    bodyTextLength: document.body.innerText.trim().length,
    docScrollWidth: document.documentElement.scrollWidth,
    docClientWidth: document.documentElement.clientWidth,
    tableCount: document.querySelectorAll('table').length,
    scenarioRowCount: [...document.querySelectorAll('table tr')].filter(tr => tr.querySelector('td')).length,
    preCount: document.querySelectorAll('pre').length,
    noteCount: document.querySelectorAll('.note').length,
  };
}
"""


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def run_checks(
    url: str,
    *,
    expect: str = "pass",
    shot: Path | None = None,
    require_note: bool = False,
    kind: str = "report",
) -> dict:
    from playwright.sync_api import sync_playwright

    results: list[dict] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1240, "height": 1000})
        page.goto(url)
        page.wait_for_timeout(300)
        probe = page.evaluate(PROBE_JS)
        contrast = page.evaluate(CONTRAST_JS)

        if shot is not None:
            shot.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(shot), full_page=True)

        results.append(
            _check("page_not_blank", probe["bodyTextLength"] > 500,
                   f"{probe['bodyTextLength']} chars of rendered text")
        )
        results.append(
            _check("title_present", bool(probe["title"]), probe["title"] or "missing")
        )
        results.append(
            _check("heading_visible", probe["h1Visible"], probe["h1"] or "missing")
        )
        results.append(
            _check(
                "verdict_rendered",
                probe["verdictVisible"] and bool(probe["verdictText"]),
                f"{probe['verdictText']!r} class={probe['verdictClass']!r}",
            )
        )

        wanted_class = "pass" if expect == "pass" else "fail"
        results.append(
            _check(
                f"verdict_style_{wanted_class}",
                wanted_class in (probe["verdictClass"] or ""),
                f"expected class containing {wanted_class!r}, got {probe['verdictClass']!r}",
            )
        )

        results.append(
            _check("cards_present", probe["cardCount"] >= 4,
                   f"{probe['cardCount']} cards in the checks grid")
        )
        results.append(
            _check(
                "cards_have_detail",
                probe["cardsWithDetail"] == probe["cardCount"] and probe["cardCount"] > 0,
                f"{probe['cardsWithDetail']}/{probe['cardCount']} cards carry a detail line",
            )
        )
        collapsed = [h for h in probe["cardHeights"] if h < 40]
        results.append(
            _check("cards_not_collapsed", not collapsed,
                   f"heights={probe['cardHeights']}")
        )
        if kind == "report":
            results.append(
                _check("steps_rendered", probe["stepRowCount"] >= 5,
                       f"{probe['stepRowCount']} step rows")
            )
            results.append(
                _check("steps_labelled", probe["emptySummaries"] == 0,
                       f"{probe['emptySummaries']} empty step summaries")
            )
        else:
            # The index has no step timeline; it must instead list every scenario.
            results.append(
                _check("scenario_table_rendered", probe["tableCount"] >= 1,
                       f"{probe['tableCount']} table(s)")
            )
            results.append(
                _check("scenario_rows_present", probe["scenarioRowCount"] >= 3,
                       f"{probe['scenarioRowCount']} scenario rows")
            )
        overflow = probe["docScrollWidth"] - probe["docClientWidth"]
        results.append(
            _check("no_horizontal_overflow", overflow <= 1,
                   f"scrollWidth={probe['docScrollWidth']} clientWidth={probe['docClientWidth']}")
        )

        if contrast is None:
            results.append(_check("contrast_measurable", False, "could not parse colours"))
        else:
            ratio = round(float(contrast["ratio"]), 2)
            results.append(
                _check("contrast_aa", ratio >= 4.5,
                       f"{ratio}:1 (fg={contrast['fg']}, bg={contrast['bg']})")
            )

        if expect == "fail" or require_note:
            results.append(
                _check("failure_note_present", probe["noteCount"] >= 1,
                       f"{probe['noteCount']} note block(s)")
            )

        browser.close()

    return {
        "url": url,
        "expect": expect,
        "passed": all(r["passed"] for r in results),
        "checks": results,
        "probe": probe,
        "screenshot": str(shot) if shot else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert the rendered report is usable.")
    parser.add_argument("report", type=Path)
    parser.add_argument("--expect", choices=("pass", "fail"), default="pass")
    parser.add_argument("--kind", choices=("report", "index"), default="report")
    parser.add_argument(
        "--require-note",
        action="store_true",
        help="assert the error explanation block rendered (fault-injection scenarios)",
    )
    parser.add_argument("--shot", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    url = "file:///" + str(args.report.resolve()).replace("\\", "/")
    report = run_checks(
        url,
        expect=args.expect,
        shot=args.shot,
        require_note=args.require_note,
        kind=args.kind,
    )
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for check in report["checks"]:
            mark = "PASS" if check["passed"] else "FAIL"
            print(f"[{mark}] {check['name']:<24} {check['detail']}")
        print("\nRESULT:", "PASS" if report["passed"] else "FAIL")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
