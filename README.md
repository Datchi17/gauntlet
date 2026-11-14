# PurpleLoop

A small, self-contained **purple-team range** you run on your own machine. An
AI-assisted attacker hits deliberately vulnerable targets, a Wazuh/Zeek SIEM
tries to detect it, and a scorer turns every run into **honest numbers** —
how much was caught, how fast, and (for the AI) how often it made things up.

> Think of it as a boxing ring where you play both fighters *and* keep the scorecard.
> Authorized lab use only — see [`docs/SCOPE.md`](docs/SCOPE.md).

## Why

Most "AI pentest" and "detection" projects *assert* they work. PurpleLoop
**measures** it, because you own both the attacks and the targets, so the ground
truth is knowable. Full rationale and plan: [`BLUEPRINT.md`](BLUEPRINT.md).

## Status

Scaffold. The scorer and detection tests run today on bundled example data:

```bash
make score     # score the example run -> coverage %, MTTD, false positives
make test      # scorer sanity + (on a Wazuh host) replay the SSH fixture
```

Milestones: **M0** lab-as-code · **M1** detection-as-code · **M2** attack harness
· **M3** the scoring loop · **M4** AI attacker, benchmarked. See the blueprint.

## Layout

```
lab/          the range: VulnHub VMs + one built target + Wazuh/Zeek (M0)
detections/   tested Wazuh/Zeek rules + fixtures + attack-map.yaml (M1)
attack/       scenarios + emitter that writes the ground-truth action log (M2)
score/        joins actions x alerts -> coverage, MTTD, false positives (M3)
ai/           LLM attacker + honest benchmark (M4)
docs/         SCOPE, threat model, BLUEPRINT, BENCHMARK
```

## Data contract

- `actions.jsonl` — one labeled record per offensive step (ground truth).
- `alerts.jsonl` — one record per SIEM alert (prediction).
- The scorer joins them on `(host, technique, time-window)`. Schemas: `BLUEPRINT.md` §5.
