#!/usr/bin/env python3
"""
Gauntlet attack runner (M2).

Runs a declarative scenario against a target and writes the ground-truth action
log (actions.jsonl) — one record per step, timestamped the moment the step starts.
That timestamp is what the scorer measures detection latency (MTTD) against.

Usage:
  python3 attack/run_scenario.py attack/scenarios/ssh-bruteforce-localhost.yaml \
      --run-id 20261115-160000 --out-dir runs/20261115-160000

Lab-only: it runs exactly the argv list in the scenario (no shell). Point it only
at hosts you own — see docs/SCOPE.md.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from emitter import Emitter  # noqa: E402

try:
    import yaml
except ImportError:
    sys.exit("needs pyyaml (ships with ansible, or: pip install pyyaml)")


def main() -> int:
    p = argparse.ArgumentParser(description="run a Gauntlet attack scenario")
    p.add_argument("scenario", type=Path)
    p.add_argument("--run-id", default=datetime.now().strftime("%Y%m%d-%H%M%S"))
    p.add_argument("--out-dir", type=Path)
    args = p.parse_args()

    sc = yaml.safe_load(args.scenario.read_text())
    target = str(sc.get("target", ""))
    agent = sc["agent"]                       # join key: the Wazuh agent on the target
    out_dir = args.out_dir or (Path("runs") / args.run_id)
    em = Emitter(out_dir / "actions.jsonl", run_id=args.run_id)

    print(f"[*] scenario '{sc['name']}'  target={target}  agent={agent}  run={args.run_id}")
    for step in sc["steps"]:
        argv = [a.replace("{target}", target) for a in step["argv"]]
        # emit the ground-truth record FIRST (ts = attack start), then execute
        em.emit(
            host=agent,
            technique=step["technique"],
            action=step["action"],
            tool=step.get("tool", ""),
            expect_detect=step.get("expect_detect", True),
        )
        print(f"[>] {step['action']} ({step['technique']}): {' '.join(argv)}")
        r = subprocess.run(argv, capture_output=True, text=True)
        print(f"    exit={r.returncode}")

    print(f"[+] ground truth -> {out_dir / 'actions.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
