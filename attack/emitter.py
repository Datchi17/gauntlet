#!/usr/bin/env python3
"""
PurpleLoop action emitter (M2).

Every offensive step the harness runs is logged here as ONE ground-truth record
in actions.jsonl. That labeled log is what makes measurement possible: the scorer
treats these as truth and the SIEM alerts as predictions.

Two ways to use it:

  # from Python (wrap each step of a scenario)
  from emitter import Emitter
  em = Emitter("runs/demo/actions.jsonl", run_id="demo")
  em.emit(host="10.10.0.12", port=22, technique="T1110.001",
          tool="hydra", action="ssh-bruteforce", expect_detect=True)

  # or from the shell, one action at a time
  python3 attack/emitter.py --out runs/demo/actions.jsonl --run-id demo \
      --host 10.10.0.12 --port 22 --technique T1110.001 \
      --tool hydra --action ssh-bruteforce --expect-detect

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


class Emitter:
    def __init__(self, out_path: str | Path, run_id: str):
        self.out = Path(out_path)
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id

    def emit(self, *, host, technique, action, tool="", port=0, expect_detect=True, ts=None):
        rec = {
            "ts": ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": host,
            "port": int(port),
            "technique": technique,
            "tool": tool,
            "action": action,
            "expect_detect": bool(expect_detect),
            "run_id": self.run_id,
        }
        with self.out.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec


def main() -> int:
    p = argparse.ArgumentParser(description="append one PurpleLoop action record")
    p.add_argument("--out", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--technique", required=True, help="MITRE ATT&CK id, e.g. T1110.001")
    p.add_argument("--tool", default="")
    p.add_argument("--action", required=True)
    p.add_argument("--expect-detect", action="store_true",
                   help="set if this step is expected to be caught by a detection")
    args = p.parse_args()

    rec = Emitter(args.out, args.run_id).emit(
        host=args.host, port=args.port, technique=args.technique,
        tool=args.tool, action=args.action, expect_detect=args.expect_detect,
    )
    print(json.dumps(rec))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
