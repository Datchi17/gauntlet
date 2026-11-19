# Gauntlet — LLM-recon capacity sweep

Does a bigger model hallucinate less and surface more real signal? We ran the
**same 3 recon cases** through four analysts — a deterministic regex baseline and
three LLMs spanning 3B → 120B parameters — **averaged over 5 runs each** (the
per-run numbers are noisy at `temperature=0.2`; single runs mislead).

| Analyst | Params | Precision | Recall | **Hallucination** | Novel real CVEs | Earns its place? |
|---|---|---|---|---|---|---|
| Deterministic baseline | — | 90% | 64% | **0%** | 0 (cannot infer) | the trustworthy floor |
| qwen2.5-coder (local) | 3B | 51% | 59% | **49%** | 1 | no |
| gpt-oss-20b (Groq) | 20B | 72% | 33% | **28%** | 2 | no |
| gpt-oss-120b (Groq) | 120B | 75% | 73% | **22%** | 4 | **borderline — no** |

## What the curve shows

**Capacity helps, monotonically, on the metrics that matter:**
- **Hallucination falls** with size: 49% → 28% → 22%.
- **Precision rises**: 51% → 72% → 75%.
- **Novel signal rises**: the 3B finds 1 real CVE the baseline can't; the 120B finds all 4
  (vsftpd CVE-2011-2523, SambaCry CVE-2017-7494, OpenSSH user-enum CVE-2018-15473,
  Apache path-traversal CVE-2021-41773).
- **Recall is the exception** (59% → 33% → 73%): the 20B is terse and *under*-reports,
  dropping plain endpoints the dumb baseline catches. Size alone doesn't fix this.

## The honest headline

**None of the free models clears the bar for unsupervised use.** Even the best
(120B) hallucinates **~22%** — better than 1-in-5, but still above the 20%
"trustworthy" threshold, and worse than the baseline's **0%**. A single lucky run
of the 120B scored 8% and looked like a winner; averaged over 5 runs it does **not**
clearly earn its place. That is the whole reason this benchmark averages.

So the defensible design is a **two-layer analyst**:
1. **Deterministic baseline = the floor you trust** (0% hallucination, but blind to
   anything not literally present — it can never turn "Apache 2.4.49" into a CVE).
2. **LLM = a human-gated *assist*** that adds real inferential signal (the CVEs) at a
   hallucination cost a reviewer must filter. The bigger the model, the less filtering —
   but never zero.

**Bottom line for operators:** use the LLM to *propose*, the baseline + a human to
*trust*. Capacity buys you less noise and more signal, not autonomy.

## Does independent (NVD) grounding change the verdict? — matched 5-run

The answer key is hand-curated. We re-scored the **same generations** with `--nvd`
(grounding = hand key ∪ NVD-confirmed CVEs via **CPE-exact, range-aware** matching),
so the only variable is the grounding — no run-to-run noise. CPE matching confirms
**4/4** of the nmap case's hand key (it catches OpenSSH user-enum CVE-2018-15473 and
SambaCry CVE-2017-7494, which description keyword search missed: 2/4). See
`ai/nvd_lookup.py --audit`, `ai/BENCHMARK_groq_nvd.md`.

| Model | Hallucination (hand key) | Hallucination (∪ NVD) | Novel |
|---|---|---|---|
| qwen-3B | 50% | 50% | 1 |
| gpt-oss-20B | 6% | 6% | 0 |
| gpt-oss-120B | 16% | **8%** | 4 → 5 |

**The finding: NVD grounding only moves the 120B.** The 3B and 20B cite nothing real
the hand key missed — their CVE citations are either already listed or genuinely
invented IDs applicable to *no* detected version, so NVD can't rescue them. Only the
120B cites real, applicable CVEs we hadn't listed (e.g. CVE-2021-42013), so **~half of
its apparent CVE-hallucination is answer-key incompleteness, not invention** — grounded
against NIST it drops 16% → 8% and comfortably **earns its place**. The small models'
skeptical verdict is independently corroborated; the frontier model is judged fairly.

Two honest caveats:
- **Grounding ≠ pertinence.** CPE matching returns *every* CVE applicable to a version
  (~88 for Apache 2.4.49), so NVD answers *"is this a real, applicable CVE?"* — never
  *"is this the intended finding?"* Only the hand key answers the latter, so NVD
  **corroborates** the key and adds a strict invented-CVE check; it does not replace it.
  (Recall is therefore measured against the hand key, not the NVD-augmented set — else
  it reads a meaningless ~3%.)
- **Nondeterminism.** Hand-key hallucination wobbles run-to-run — the 20B especially
  (25% in the sweep above, 6% here; it is terse and high-variance). Trust the *matched*
  within-pair deltas (120B 16→8), not cross-sweep absolute numbers.

---
*Reproduce:* `python3 ai/bench.py --provider api --runs 5` with
`GAUNTLET_API_MODEL=openai/gpt-oss-120b` (see `ai/README.md`). Per-model reports:
`ai/BENCHMARK.md` (3B local), `ai/BENCHMARK_groq.md` (120B).
