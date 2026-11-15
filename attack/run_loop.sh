#!/usr/bin/env bash
# Gauntlet: run one scenario end-to-end — attack -> pull alerts -> score.
#   ./attack/run_loop.sh attack/scenarios/ssh-bruteforce-localhost.yaml
# Produces runs/<id>/{actions.jsonl,alerts.jsonl,report.md}.
set -euo pipefail
SCENARIO="${1:?usage: run_loop.sh <scenario.yaml>}"
RID="$(date +%Y%m%d-%H%M%S)"
DIR="runs/$RID"

python3 attack/run_scenario.py "$SCENARIO" --run-id "$RID" --out-dir "$DIR"
echo "[*] waiting 20s for alerts to propagate to the manager..."
sleep 20
python3 score/pull_alerts.py --run-dir "$DIR"
python3 score/scorer.py --actions "$DIR/actions.jsonl" --alerts "$DIR/alerts.jsonl" --md "$DIR/report.md"
echo "[+] report: $DIR/report.md"
