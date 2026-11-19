# Gauntlet

**An honest scoreboard for AI in detection.** A small, self-contained purple-team
range you run on one machine: an AI-assisted attacker hits deliberately vulnerable
targets, a Wazuh/Zeek SIEM tries to catch it, and a scorer turns every run into
numbers you can trust — how much was caught, how fast, how many false alarms, and
(for the AI) how often it invents things that aren't there.

> A boxing ring where you play both fighters *and* keep the scorecard.
> Authorized lab use only — see [`docs/SCOPE.md`](docs/SCOPE.md).

## The sharpest result so far — a pilot, not a verdict

The most interesting finding is about the AI, not the lab: **a small local model
(3B) invents fake CVEs ~50% of the time when reading scan output; a 120B model
~8%.** Hallucination falls with model capacity, novel-signal rises, and grounding
each cited CVE against NIST's NVD cuts apparent hallucination further. This is a
**pilot — n=3 recon cases, author-scored** — so treat the *shape* as a signal, not
a settled measurement. Full method + numbers: [`ai/CAPACITY.md`](ai/CAPACITY.md).

## What's actually proven (honest status)

The motto is *measure, don't assert*, so the project holds itself to the same bar.
This table is **generated** from `detections/attack-map.yaml` (run `make status`),
so it can't drift from the truth:

**1 of 15 detections are live-validated** (tripped by a real attack and scored
end-to-end); the other 14 fire on hand-written fixtures via `wazuh-logtest` but are
**not yet proven against a real attack** — that proves the rule's *logic*, not the
end-to-end claim. Live detections cover **1 of 9** ATT&CK techniques (T1110.001).

| Validation | Technique | Detection | Source | Rule |
|---|---|---|---|---|
| ✅ live | T1110.001 | SSH brute force (non-existent user) | wazuh | 100200 |
| 🧪 fixture | T1110.001 | SSH brute force (wrong password) | wazuh | 100201 |
| 🧪 fixture | T1110.001 | Compromise: SSH success from a brute-forcing IP | wazuh | 100202 |
| 🧪 fixture | T1078 | Valid Accounts: successful SSH authentication | wazuh | 100203 |
| 🧪 fixture | T1548.003 | Unauthorized sudo attempt | wazuh | 100210 |
| 🧪 fixture | T1548.003 | Sudo brute force (repeated unauthorized) | wazuh | 100211 |
| 🧪 fixture | T1548.003 | Successful sudo to root | wazuh | 100212 |
| 🧪 fixture | T1136.001 | Create local account | wazuh | 100220 |
| 🧪 fixture | T1136.001 | Create ROOT-level account (uid=0 backdoor) | wazuh | 100221 |
| 🧪 fixture | T1136.001 | Create new group | wazuh | 100222 |
| 🧪 fixture | T1053.003 | Cron: root crontab modified | wazuh | 100230 |
| 🧪 fixture | T1098 | Account Manipulation: password changed | wazuh | 100240 |
| 🧪 fixture | T1046 | Network Service Scanning (nmap) | zeek | 100301 |
| 🧪 fixture | T1190 | Exploit Public-Facing Application (web RCE) | zeek | 100310 |
| 🧪 fixture | T1548.001 | Abuse Elevation Control: SUID-root execution | wazuh-auditd | 100320 |

## Honest limitations (read before trusting a number)

- **Single box.** The attacker, target and SIEM currently share one host, so the
  measured MTTD (~2 s) and **0 % false-positive rate are localhost artifacts, not
  field numbers** — with no benign background traffic there is nothing to raise a
  false positive. A second target + a benign-traffic generator are needed to make
  MTTD/FP mean anything. (In progress — see the roadmap.)
- **LLM pilot.** The hallucination curve rests on 3 cases with an answer key the
  author wrote. The fix is ~30 cases from real recon with a held-out, NVD-grounded
  key. Until then: a promising shape, not a thesis-grade finding.

## Why it exists

Most "AI pentest" and "detection" projects *assert* they work. Gauntlet **measures**
it, because you own both the attacks and the targets, so the ground truth is
knowable. Full rationale and plan: [`BLUEPRINT.md`](BLUEPRINT.md).

## Run it

```bash
make status    # the honest coverage table above (live vs fixture)
make score     # score the example run -> coverage %, MTTD, false positives
make test      # scorer sanity + (on a Wazuh host) replay the SSH fixture
python3 ai/bench.py --provider api --nvd   # the AI benchmark (bring a free Groq key)
```

## Layout

```
lab/          the range: VulnHub VMs + one built target + Wazuh/Zeek (M0)
detections/   tested Wazuh/Zeek rules + fixtures + attack-map.yaml (M1)
attack/       scenarios + emitter that writes the ground-truth action log (M2)
score/        joins actions x alerts -> coverage, MTTD, false positives (M3)
ai/           LLM-recon benchmark + NVD CVE grounding (M4)
docs/         SCOPE, threat model, BLUEPRINT, BENCHMARK
```

## Data contract

- `actions.jsonl` — one labeled record per offensive step (ground truth).
- `alerts.jsonl` — one record per SIEM alert (prediction).
- The scorer joins them on `(host, technique, time-window)`. Schemas: `BLUEPRINT.md` §5.
