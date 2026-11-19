# Gauntlet — roadmap (post-council audit, 2026-11-19)

This encodes an LLM-council audit of the project into a sequenced plan. The gating
decision at the top reorders everything below, so answer it first.

## 0. The gating decision: thesis or portfolio?

| If the goal is… | then the spine is… | and… |
|---|---|---|
| **Thesis** | the falsifiable LLM-measurement question (*does model capacity reduce recon hallucination?*) | grow n, add blind ground truth, frame novelty vs prior art; the SIEM is supporting apparatus. Depth > breadth. |
| **Portfolio / job** | the live purple-team loop across ~6 techniques + a clean README | the hallucination curve is a memorable bonus, not the headline. Breadth of *honest* live coverage wins the 30-second skim. |

Either way the fixes below apply; the decision only changes how far to push each.

## 1. Done now — zero disk / RAM / API  ✅

- [x] **Honest README**: names the spine ("an honest scoreboard for AI in detection"),
      labels the LLM finding a **pilot (n=3)**, states the single-box limitation up front.
- [x] **`validation: live|fixture`** in `attack-map.yaml`; **`make status`** generates the
      coverage table so it can never drift. Current truth: **1 live / 14 fixture**, 1 of 9
      techniques live.

## 2. The root cause to repair: author-is-grader

The council's unifying finding — the author writes both the fixture *and* the rule,
both the answer key *and* its audit. The one fix that repairs both halves is **ground
truth the author didn't write**:
- **Detections:** live-fire, but NOT on the same box — that only yields more localhost
  artifacts. Needs a second target + benign traffic so FP/MTTD are real.
- **LLM study:** grow 3 → ~20–30 cases from **real recon** (scan VulnHub boxes), answer
  key grounded in **NVD + public writeups**, not hand-authored.

## 3. This week — after freeing ~5–7 GB (`docker builder prune -af`)

- [ ] Stand up a **second target as a Docker container** (fits under disk pressure; no VM).
- [ ] Wire **Atomic Red Team** local executors for ~5–6 techniques already in the catalog
      (T1136 account creation, T1548.003 sudo, T1053.003 cron, T1046 scan, T1190 web).
- [ ] Add a **benign-traffic generator** (periodic normal logins / web hits) so the
      false-positive number is *earned*, not a byproduct of silence.
- [ ] Re-run the loop live → flip those techniques from 🧪 fixture to ✅ live in
      `attack-map.yaml`; `make status` updates itself.
- **Target: 1 → ~6 live techniques, with a non-zero, honest FP rate.**

## 4. This month

- [ ] Grow the LLM benchmark to ~20–30 real-recon cases with a held-out, NVD-grounded key.
- [ ] `make live` — one reproducible command for the whole end-to-end live run.
- [ ] **Novelty framing** vs prior art (Atomic Red Team, existing Wazuh purple-team labs):
      what's new here = the *grounded-hallucination measurement* + the *honest scoring* harness.
- [ ] Off-box backup of lab/VM state (code is on GitHub; the running range is not).

## 5. Explicitly NOT now — council consensus

- ✗ Co-run a big local model with the SIEM (16 GB won't hold both — time-share instead).
- ✗ Polish the LLM benchmark further before growing n (polish isn't the weakness; n is).
- ✗ Add a 16th detection — breadth you can't validate is a liability.
- ✗ Publish the hallucination curve as a headline until n ≈ 30 with a held-out key.
