#!/usr/bin/env python3
"""Print Gauntlet's honest detection-coverage table from detections/attack-map.yaml.

The headline distinction is `validation`:
  live    = tripped end-to-end by a REAL attack and scored by the loop.
  fixture = the rule fires on a hand-written sample log via wazuh-logtest, but has
            NOT yet been proven against a real attack.

This is generated, not typed by hand, so the README can never drift from the truth.
Usage: python3 detections/coverage_report.py [--markdown]   (markdown is the default)
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAP = HERE / "attack-map.yaml"

BADGE = {"live": "✅ live", "fixture": "🧪 fixture"}


def load() -> list[dict]:
    try:
        import yaml
    except ImportError:
        sys.exit("needs pyyaml (pip install pyyaml)")
    return yaml.safe_load(MAP.read_text())["coverage"]


def render(rows: list[dict]) -> str:
    live = [r for r in rows if r.get("validation") == "live"]
    fixture = [r for r in rows if r.get("validation") != "live"]
    techniques = sorted({r["technique"] for r in rows})
    live_techs = sorted({r["technique"] for r in live})
    out = [
        "## Detection coverage — what's proven vs. what's staged",
        "",
        f"**{len(live)} of {len(rows)} detections are live-validated** "
        f"(tripped by a real attack and scored end-to-end); the rest fire on "
        f"hand-written fixtures via `wazuh-logtest` but are **not yet proven against "
        f"a real attack.** Honest status, generated from `detections/attack-map.yaml`.",
        "",
        f"- Techniques with ≥1 **live** detection: **{len(live_techs)} / {len(techniques)}** "
        f"({', '.join(live_techs) or '—'})",
        f"- Detections: **{len(live)} live**, **{len(fixture)} fixture-only**",
        "",
        "| Validation | Technique | Detection | Source | Rule |",
        "|---|---|---|---|---|",
    ]
    for r in live + fixture:
        rids = ", ".join(str(x) for x in r.get("rule_ids", []))
        out.append(f"| {BADGE.get(r.get('validation'), '🧪 fixture')} | {r['technique']} "
                   f"| {r['name']} | {r['source']} | {rids} |")
    return "\n".join(out) + "\n"


def main() -> int:
    print(render(load()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
