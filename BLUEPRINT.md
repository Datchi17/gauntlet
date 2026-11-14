# PurpleLoop — Blueprint v1.1

> Working name; rename freely. A reproducible, **lab-as-code** security range where an
> AI-assisted offensive agent attacks disposable targets, a Wazuh/Zeek SIEM tries to detect
> it, and every run emits **honest, versioned metrics** on both sides — closing the
> purple-team loop.

This document is the plan, not the code. It defines the thesis, the architecture, the
measurement discipline, and a milestone path you can build against one weekend at a time.

> **v1.1** — lab rebased onto the user's existing VulnHub stash (`~/Downloads/Test Machines/`)
> instead of building targets from scratch: it's now a **mixed VM lab** (VulnHub VMs + one
> built target + Wazuh/Zeek), not Docker-only. See §3 M0 and the starter-box table.

---

## 1. Thesis (why this is research-grade, not a demo)

Most "AI pentest" and "detection" projects **assert** value; they don't **measure** it.
PurpleLoop's single contribution is *measurement discipline*, made possible because you own
both the attacks and the targets, so the ground truth is knowable:

- **Offense:** does the LLM layer add signal over plain tooling — and how often does it lie?
  (precision / recall / novel-signal / **hallucination rate** against a known-vuln inventory)
- **Defense:** what fraction of a known attack set is actually caught, with what latency and
  what false-positive cost? (ATT&CK coverage / MTTD / FP rate)
- **The loop:** a regenerated-every-run **coverage matrix** (attack technique × detection) and
  mean-time-to-detect — the one picture that tells the whole offense-and-defense story.

Because the lab is reproducible and the attacks are labeled, the numbers are **falsifiable and
repeatable** — which is exactly what's missing from the field, and exactly the "validation-first
/ go-no-go gate" instinct you already shipped in ReconAI, elevated into a real benchmark.

It replaces nothing you lost with GRFICS: ICS was the *stage*. The substance — attack → detect
→ measure — is domain-agnostic, and rebasing it on **lab-as-code** fixes the problem that just
bit you: deleting machines now costs nothing, because one command rebuilds the whole range.

---

## 2. Architecture

```text
  provision (Ansible)            attack                     detect                    measure
 ┌──────────────────┐   ┌────────────────────┐   ┌────────────────────┐   ┌────────────────────┐
 │ lab-as-code      │   │ offensive harness   │   │ SIEM sensor         │   │ scorer              │
 │ VMs + Ansible    │──►│ ReconAI chain + LLM │──►│ Wazuh + Zeek        │──►│ coverage matrix     │
 │ targets + SIEM   │   │ emits LABELED acts  │   │ emits alerts        │   │ MTTD, FP, halluc.   │
 └──────────────────┘   └─────────┬──────────┘   └──────────┬─────────┘   └─────────┬──────────┘
         ▲                        │ actions.jsonl            │ alerts.jsonl          │ report.md
         │                        │ (ground truth)           │ (predictions)         │
         └──────────────────── feedback: undetected techniques → new detection fixtures ◄──┘
```

### The one idea that makes it work: the ground-truth action log

The offensive harness emits a **structured, timestamped record of every action it takes**
(technique, target host, port, timestamp, ATT&CK ID, `expect_detect: true|false`). The SIEM
emits its alerts. The scorer **joins the two** on `(time-window, host, technique)`:

- attacks are **labeled ground truth**,
- alerts are **predictions**,
- everything downstream is a plain classification-metrics problem (TP / FN / FP + latency).

This join is the heart of the project. Get the two log schemas right (§5) and the metrics fall
out cleanly. Get them vague and nothing downstream is trustworthy — so this is where to spend
your care.

---

## 3. Milestones — "a few sharp smaller projects"

Each milestone is independently shippable as its own GitHub-worthy result **and** composes into
the flagship. Build in this order on purpose: **defense and a deterministic baseline come first,
so you have ground truth before you ever point an LLM at anything** (same discipline as ReconAI's
go/no-go gate).

| # | Ship name (standalone) | What's done | ~effort |
|---|---|---|---|
| **M0** | *lab-as-code range* | one command brings SIEM + VulnHub targets + built target to a known snapshot; snapshot-revert to reset | 1–2 wk |
| **M1** | *tested-detection lab* | Wazuh+Zeek rules, each with a replayable fixture + CI that fails if a rule stops firing; ATT&CK map; FP rate vs benign noise | 1–2 wk |
| **M2** | *attack harness + ground truth* | ReconAI chain wrapped with an action emitter; deterministic scripted scenarios → `actions.jsonl` (no AI yet) | 1 wk |
| **M3** | *purple-team range* (flagship) | the scorer: join actions ⨝ alerts → coverage matrix, MTTD, FP; `report.md`; gaps become new fixtures | 1–2 wk |
| **M4** | *AI pentest benchmark* (research payload) | LLM agent proposes/triages steps; benchmarked vs M2 baseline for precision/recall/novel-signal/**hallucination**; local vs frontier → `BENCHMARK.md` | 2 wk |

Ship after M1 (a tested detection lab is already rare on student GitHubs), again after M3 (the
full loop), and again after M4 (the publishable benchmark). Three distinct releases, one story.

### M0 — Lab-as-code (the foundation)
A **mixed VM lab** on a host-only network, not Docker-only — because the targets are the
VulnHub VMs you already have (`~/Downloads/Test Machines/`), so there's nothing to rebuild.
- **Targets:** imported VulnHub VMs (see the starter-box table below) **+ one built Ubuntu
  target** you provision with Ansible (reuse `ansible-linux-lab`) as the clean host-detection box.
- **SIEM stack:** Wazuh single-node + Zeek — run as containers or a small VM, agents pushed to
  the agent-capable targets, Zeek sniffing the whole host-only segment.
- **Orchestration-as-code:** Ansible provisions the SIEM and the built target, pins NTP, and
  scripts `VBoxManage import` + **snapshot revert** for the VulnHub images (that's your
  "rebuild" button for pre-built images — see the reproducibility caveat in §9).
- **Done when:** one command brings the SIEM + targets up to a known snapshot and the SIEM is
  receiving both Zeek network events and agent logs.

#### Starter boxes (picked from your `~/Downloads/Test Machines/` stash)
Chosen for: known/documented vulns (**ground truth**), attack chains that generate *detectable*
events (brute-force, web RCE, reverse shells, privesc), and whether the OS can carry a Wazuh agent.

| Box | Attack chain (ground truth) | Agent? | Role in PurpleLoop |
|---|---|---|---|
| **DC-1** | Drupalgeddon2 web RCE → `www-data` → SUID `find` privesc | ✅ Debian ~2019 | primary host+network target |
| **Basic Pentesting 1** | weak FTP/SSH creds + SSH brute-force → Linux privesc | ✅ Ubuntu | validates your SSH brute-force rule → M1 **fixture #1** |
| **Symfonos 1** | SMB → LFI → SMTP log-poisoning → shell → PATH privesc | ✅ Debian | **you already wrote its report** = ground truth in hand |
| **mr-robot** | WordPress brute-force → wp shell → SUID `nmap` privesc | ✅ Ubuntu ~2015 | rich web + brute-force signal |
| **Kioptrix L1 (+L2)** | ancient Apache/Samba RCE, SQLi | ❌ too old (Linux 2.4 / RH) | **network-only** — proves Zeek-for-all works when no agent can |
| *built Ubuntu target* | seed exactly the vulns you want | ✅ clean | controlled host-detection + pinned clock for MTTD |

- **"Agent?" is a first-boot check, not a promise** — confirming the agent installs is literally
  an M0 task. Verified ages: Kioptrix L1 = Linux 2.4, L2 = old Red Hat, Kioptrix2014 = FreeBSD →
  all network-only.
- **Bonus ground truth:** you also have a *Kioptrix L3* report — keep L3 as an extra network-only
  target whose answer key you've already written.
- **Deferred for later breadth:** DC-2…9 (more Debian targets), Tr0ll 1–3 and Brainpan 1–3
  (buffer-overflow / CTF-trolly — weak detection value), Kioptrix2014 (FreeBSD agent pain),
  Lampiao (DirtyCow — good *later* as a deliberately "hard to detect" case).

### M1 — Detection-as-Code (defensive spine)
- Author/port Wazuh + Zeek rules. **Every rule ships with a fixture** — a PCAP or log sample that
  *should* trip it — and a test asserting it fires. Your existing SSH brute-force rule is fixture #1.
- GitHub Actions replays fixtures against the engine → red/green (the CI you keep listing in your
  repos' "pour aller plus loin" sections — here it's core, not a nicety).
- `attack-map.yaml`: rule ↔ MITRE ATT&CK (Enterprise) technique.
- Measure per-rule **FP rate** against a benign-noise generator (normal SSH logins, routine web
  traffic), so "it detects" is paired with "and how noisy it is."
- **Done when:** `pytest`/CI is green and `attack-map.yaml` shows your coverage.

### M2 — Attack harness + ground-truth log (offensive spine)
- Wrap ReconAI's declarative chain; add an **action emitter** writing one `actions.jsonl` record
  per executed step (§5 schema).
- Start with **deterministic, scripted scenarios** — no AI. This is the baseline M4 is measured
  against, and the ground truth M3 scores against.
- **Done when:** running a scenario yields a well-formed `actions.jsonl`.

### M3 — The scorer + the loop (flagship integration)
- Join `actions.jsonl` ⨝ `alerts.jsonl` → confusion matrix, per-technique coverage, MTTD, FP.
- Emit `report.md`: the coverage matrix (technique × detected?), the numbers, the gaps.
- **Feedback step:** each undetected technique opens an issue / seeds a new M1 fixture. That edge
  in the diagram is what makes it a *loop*, not a pipeline.
- **Done when:** `purpleloop run <scenario>` produces a report a stranger can read in 30 seconds.

### M4 — The AI layer, honestly benchmarked (the research payload)
- Add the LLM agent (ReconAI's AI layer) that proposes/triages attack steps.
- Benchmark it against the M2 deterministic baseline **on the same ground truth**:
  precision, recall, novel-signal, hallucination rate (§4).
- Compare **local (Ollama)** vs **one frontier model**; redact detected secrets before any remote
  call, exactly as ReconAI already does.
- **Done when:** `BENCHMARK.md` states, with numbers, whether the AI layer earned its place.

---

## 4. Metrics (define precisely — this is the core)

Each metric gets a definition, a measurement method, and an honest caveat. Vague metrics are
worse than none.

| Metric | Definition | Caveat |
|---|---|---|
| **Detection coverage** | detected techniques ÷ attempted techniques, per ATT&CK technique | lab signal is cleaner than production; coverage here is an upper bound |
| **MTTD** | median(`alert_time − action_time`) over detected actions | sensitive to clock skew on old VMs — pin NTP, and prefer Zeek timestamps (sensor clock) which sidestep the target's clock entirely |
| **FP rate** | false alerts ÷ benign events, over a benign-noise window | only as good as how realistic the benign generator is |
| **Offensive precision** | true findings ÷ all findings reported by the agent | ground truth = the vuln inventory *you* built into the lab |
| **Offensive recall** | true findings ÷ all seeded vulns | only counts vulns you deliberately planted |
| **Hallucination rate** | findings referencing a nonexistent CVE/endpoint/host ÷ all findings | the headline AI-risk number; needs the known-good lab inventory to judge |
| **Novel-signal** | true findings the AI surfaced that the deterministic baseline missed | the only thing that justifies the AI layer existing |

---

## 5. Data contracts (freeze these early)

**`actions.jsonl`** — one line per executed offensive step (ground truth):
```json
{"ts":"2026-11-14T18:30:00Z","host":"10.10.0.11","port":22,"technique":"T1110.001",
 "tool":"hydra","action":"ssh-bruteforce","expect_detect":true,"run_id":"abc123"}
```

**`alerts.jsonl`** — one line per SIEM alert, normalized from Wazuh/Zeek:
```json
{"ts":"2026-11-14T18:30:04Z","host":"10.10.0.11","rule_id":"100200",
 "technique":"T1110.001","source":"wazuh","severity":10,"run_id":"abc123"}
```

The scorer joins on `technique` + `host` within a time window (e.g. action_time ≤ alert_time ≤
action_time + N s). Both files carry `run_id` so a run is fully reproducible and self-contained.

---

## 6. Repo layout

```text
purple-loop/
  lab/                # M0: the range (mixed VMs, host-only network)
    targets/          #   VulnHub import + snapshot-revert scripts; one built Ubuntu target
    siem/             #   wazuh single-node + zeek
    ansible/          #   provisioning + NTP + agent push (reuse ansible-linux-lab)
  detections/         # M1: the defensive spine
    rules/            #   wazuh + zeek rules
    fixtures/         #   replayable PCAP/log samples, one per rule
    attack-map.yaml   #   rule ↔ ATT&CK technique
  attack/             # M2: the offensive spine
    scenarios/        #   deterministic scripted attacks
    emitter.py        #   writes actions.jsonl
  score/              # M3: the joiner + report generator
  ai/                 # M4: LLM agent + benchmark
  docs/
    BLUEPRINT.md      #   this file
    SCOPE.md          #   authorized-use, lab-only (see §7)
    THREAT-MODEL.md
    BENCHMARK.md      #   the research output (M4)
  .github/workflows/  # detection CI (M1)
  Makefile            # up / down / run / score
```

---

## 7. Scope & ethics (lab-only, by construction)

- The offensive layer runs **only** against the bundled disposable range. Mirror ReconAI's
  `--i-am-authorized` discipline: a target outside the lab's own CIDR is refused.
- Targets are things you own and ship in-repo; no external hosts, ever.
- Secrets detected during a run are redacted before any remote-model call (reuse ReconAI's path).
- `SCOPE.md` states all of the above in plain language — same spirit as your network-inventory
  "Sécurité et éthique" section.

---

## 8. Tech choices (reuse your stack)

| Piece | Choice | Why |
|---|---|---|
| Range | VirtualBox VMs + Ansible (Docker for the SIEM/built target) | reuse `ansible-linux-lab` + your existing VulnHub stash; revert via snapshots, keep the `.ova/.zip` archives |
| SIEM | Wazuh (single-node) + Zeek | you've already shipped rules for both in `grficsv2-siem` |
| Attack chain | ReconAI's declarative `tools.yaml` + Python | reuse; add only the action emitter |
| Scorer | Python **stdlib** (pandas only if it truly earns it) | matches `network-inventory`'s zero-dep taste; keeps it auditable |
| AI | Ollama local + optional frontier via API key | reuse ReconAI's provider layer and redaction |
| CI | GitHub Actions | the "pour aller plus loin" item from three of your repos, finally core |

---

## 9. Limits (state them up front — your house style)

- Single-node Wazuh is not SOC scale; this measures *rule logic*, not operations.
- Lab detection ≠ production detection: clean, low-noise signal flatters coverage numbers.
- The ground-truth join is time+host+technique based; clock skew and chatty techniques can
  mislabel — pin NTP and document every mislabel you find.
- The hallucination metric depends on a complete known-good inventory of the lab — you have it,
  because the VulnHub boxes are documented and you've written reports for some.
- **VulnHub images aren't rebuildable from code.** Reproducibility here = keeping the `.ova/.zip`
  archives + a scripted import/snapshot-revert, *not* a playbook that builds the OS. Lose both
  the VM and the archive and you re-download. Only the *built* Ubuntu target is true lab-as-code.
- **Host-detection coverage is only claimed on agent-capable boxes.** Ancient targets
  (Kioptrix L1/L2, Kioptrix2014/FreeBSD) are network-only; their coverage comes from Zeek alone.
- A mixed VM lab is heavier than containers: reverting is a snapshot restore, slower than a
  `make down`/`make up`.
- Small target set in v1; coverage claims are scoped to what you planted, nothing more.

---

## 10. What you'll learn (and why it's hireable)

- **M0** — reproducible security infrastructure as code: the exact skill whose absence just cost
  you the GRFICS lab.
- **M1** — detection engineering *with testing discipline* (detection-as-code), which almost no
  student portfolio demonstrates.
- **M2/M3** — security-telemetry data engineering and the measurement mindset.
- **M4** — rigorous LLM evaluation (hallucination, novel-signal) — genuinely rare and sought-after.

---

## 11. Origin

A deliberate convergence of five existing projects — `reconai` (AI attack chain + validation
gate), `grficsv2-siem` (Wazuh/Zeek detection engineering), `ansible-linux-lab` (provisioning),
`network-inventory` (safe, zero-dep tooling), and `Cyber-News-Dashboard` (threat-intel framing) —
into one measured, reproducible purple-team loop. Rebased off ICS onto the user's existing
VulnHub stash + one built target, so the range reuses ~26 GB of already-downloaded, documented
boxes and resets by snapshot instead of being rebuilt from nothing.
