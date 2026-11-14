# score/ — the loop (M3)

`scorer.py` joins `actions.jsonl` (ground truth) to `alerts.jsonl` (predictions)
and reports coverage, MTTD, and false positives. Runs today on `examples/`:

    python3 score/scorer.py --md report.md
