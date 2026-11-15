#!/usr/bin/env python3
"""
Gauntlet scorer — the heart of the loop (M3).

Joins the attacker's ground-truth action log (actions.jsonl) to the SIEM's
alert log (alerts.jsonl) on (host, technique, time-window), then computes the
honest metrics the whole project exists to produce:

  - detection coverage  : detected techniques / attempted (expect_detect) techniques
  - MTTD                : median(alert_time - action_time) over detected actions
  - false positives     : alerts that match no attacker action
  - a per-technique table (detected / missed) you can paste into a report

Stdlib only, on purpose (same zero-dependency taste as network-inventory).

Usage:
  python3 score/scorer.py                                   # runs on score/examples/
  python3 score/scorer.py --actions a.jsonl --alerts b.jsonl --window 120
  python3 score/scorer.py ... --md report.md                # also write a report
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def parse_ts(s: str) -> datetime:
    """Parse an ISO-8601 timestamp; tolerate a trailing Z."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open() as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                sys.exit(f"{path}:{n}: bad JSON line: {e}")
    return rows


def score(actions: list[dict], alerts: list[dict], window: int) -> dict:
    """Match each action to the first alert on same (host, technique) within
    [action_ts, action_ts + window seconds]. Returns a result dict."""
    alerts_unused = list(alerts)  # anything left over at the end is a false positive
    per_action = []

    for a in actions:
        a_ts = parse_ts(a["ts"])
        match = None
        for al in alerts_unused:
            if al.get("host") != a.get("host"):
                continue
            if al.get("technique") != a.get("technique"):
                continue
            latency = (parse_ts(al["ts"]) - a_ts).total_seconds()
            if 0 <= latency <= window:
                match = (al, latency)
                break
        if match is not None:
            alerts_unused.remove(match[0])
        per_action.append(
            {
                "host": a.get("host"),
                "technique": a.get("technique"),
                "action": a.get("action"),
                "expected": bool(a.get("expect_detect", True)),
                "detected": match is not None,
                "latency": None if match is None else match[1],
            }
        )

    expected = [r for r in per_action if r["expected"]]
    detected = [r for r in expected if r["detected"]]
    latencies = [r["latency"] for r in detected if r["latency"] is not None]

    # per-technique rollup
    techniques: dict[str, dict] = {}
    for r in expected:
        t = techniques.setdefault(r["technique"], {"attempted": 0, "detected": 0})
        t["attempted"] += 1
        t["detected"] += 1 if r["detected"] else 0

    return {
        "n_actions": len(actions),
        "n_expected": len(expected),
        "n_detected": len(detected),
        "coverage": (len(detected) / len(expected)) if expected else 0.0,
        "mttd": statistics.median(latencies) if latencies else None,
        "false_positives": len(alerts_unused),
        "techniques": techniques,
        "per_action": per_action,
    }


def render_md(res: dict, window: int) -> str:
    cov = f"{res['coverage'] * 100:.0f}%"
    mttd = "n/a" if res["mttd"] is None else f"{res['mttd']:.1f}s"
    lines = [
        "# Gauntlet run report",
        "",
        f"- **Detection coverage:** {cov}  ({res['n_detected']}/{res['n_expected']} expected techniques caught)",
        f"- **MTTD (median):** {mttd}",
        f"- **False positives:** {res['false_positives']}  (alerts matching no action)",
        f"- **Join window:** {window}s",
        "",
        "## Coverage by technique",
        "",
        "| Technique | Attempted | Detected | Result |",
        "|---|---|---|---|",
    ]
    for tech, c in sorted(res["techniques"].items()):
        ok = "✅" if c["detected"] == c["attempted"] else ("⚠️" if c["detected"] else "❌")
        lines.append(f"| {tech} | {c['attempted']} | {c['detected']} | {ok} |")
    gaps = [t for t, c in res["techniques"].items() if c["detected"] < c["attempted"]]
    lines += ["", "## Gaps to close (feed back into M1)", ""]
    lines += [f"- `{g}` — no (or partial) detection; add a rule + fixture" for g in gaps] or ["- none 🎉"]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Gauntlet scorer")
    p.add_argument("--actions", type=Path, default=HERE / "examples" / "actions.jsonl")
    p.add_argument("--alerts", type=Path, default=HERE / "examples" / "alerts.jsonl")
    p.add_argument("--window", type=int, default=120, help="join window in seconds")
    p.add_argument("--md", type=Path, help="also write the markdown report here")
    args = p.parse_args()

    res = score(load_jsonl(args.actions), load_jsonl(args.alerts), args.window)
    report = render_md(res, args.window)
    print(report)
    if args.md:
        args.md.write_text(report)
        print(f"[+] wrote {args.md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
