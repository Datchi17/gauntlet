#!/usr/bin/env python3
"""
Gauntlet alert puller (M2 -> M3 bridge).

Reads the manager's real alerts for a run and normalizes them to alerts.jsonl,
filtered to the detection rules WE own (from attack-map.yaml). Filtering to our
rules keeps the score about Gauntlet's detections, not Wazuh's entire built-in
ruleset (otherwise every base event would look like a false positive).

Usage:
  python3 score/pull_alerts.py --run-dir runs/<id>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("needs pyyaml (ships with ansible, or: pip install pyyaml)")

ROOT = Path(__file__).resolve().parent.parent
ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"


def parse_ts(s: str) -> datetime:
    """Tolerate Wazuh's '+0000' (no colon) and trailing 'Z'."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    elif len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def detect_manager() -> str:
    out = subprocess.run(
        ["docker", "ps", "--filter", "name=wazuh.manager", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    names = out.stdout.split()
    if not names:
        sys.exit("no running wazuh.manager container found")
    return names[0]


def main() -> int:
    p = argparse.ArgumentParser(description="pull + normalize manager alerts for a run")
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--attack-map", type=Path, default=ROOT / "detections" / "attack-map.yaml")
    p.add_argument("--manager", default=None, help="manager container (auto-detected by default)")
    args = p.parse_args()

    # which rule ids do WE own, and what technique does each cover?
    amap = yaml.safe_load(args.attack_map.read_text())
    rule_ids: set[str] = set()
    tech_by_rule: dict[str, str] = {}
    for c in amap.get("coverage", []):
        for rid in (c.get("rule_ids") or []):
            rule_ids.add(str(rid))
            tech_by_rule[str(rid)] = c["technique"]
    if not rule_ids:
        sys.exit("attack-map.yaml has no implemented rule_ids to pull")

    # run window: from the earliest action, minus a small buffer
    actions = [json.loads(l) for l in (args.run_dir / "actions.jsonl").read_text().splitlines() if l.strip()]
    if not actions:
        sys.exit(f"no actions in {args.run_dir / 'actions.jsonl'}")
    run_id = actions[0].get("run_id", "")
    since = min(parse_ts(a["ts"]) for a in actions) - timedelta(seconds=5)

    mgr = args.manager or detect_manager()
    raw = subprocess.run(["docker", "exec", mgr, "cat", ALERTS_PATH], capture_output=True, text=True)
    if raw.returncode != 0:
        sys.exit(f"could not read {ALERTS_PATH} from {mgr}: {raw.stderr[:200]}")

    out_path = args.run_dir / "alerts.jsonl"
    n = 0
    with out_path.open("w") as out:
        for line in raw.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = a.get("rule", {})
            rid = str(rule.get("id", ""))
            if rid not in rule_ids:
                continue
            ts = parse_ts(a["timestamp"])
            if ts < since:
                continue
            mitre = (rule.get("mitre") or {}).get("id") or []
            rec = {
                "ts": ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "host": a.get("agent", {}).get("name", ""),
                "rule_id": rid,
                "technique": mitre[0] if mitre else tech_by_rule.get(rid, ""),
                "source": "wazuh",
                "severity": rule.get("level", 0),
                "run_id": run_id,
            }
            out.write(json.dumps(rec) + "\n")
            n += 1

    print(f"[+] pulled {n} alert(s) for our rules {sorted(rule_ids)} -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
