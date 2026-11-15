# Gauntlet LLM-recon benchmark

- **Model under test:** qwen2.5-coder:3b
- **Cases:** 3 × 5 run(s) = 15 scored passes
- **Verdict:** this model **does NOT clearly earn its place** — novel signal 1 distinct real findings vs 8.0 hallucinated/run (49% of what it cited).

| Metric | Deterministic baseline | LLM |
|---|---|---|
| Precision (grounded & correct / cited) | 90% | 51% |
| Recall (answer-key entities found) | 64% | 59% |
| **Hallucination rate** (invented / cited) | 0% | 49% |
| Entities cited | 50 | 81 |

**Novel signal** — real entities the LLM surfaced that the baseline could not (1): CVE-2017-7494

## Per-case (mean of 5 runs)

| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |
|---|---|---|---|---|
| nmap-services | 6.8 | 0.2 | 6.6 | 0.0 |
| http-recon | 5.8 | 5.0 | 0.8 | 5.0 |
| js-recon | 3.6 | 3.0 | 0.6 | 4.0 |

## Reading this

The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by construction — that gap is the LLM's opportunity (**novel signal**). The price is the **hallucination rate**: entities the LLM cited that aren't in the evidence. A useful AI layer is one whose novel signal clearly outweighs its hallucination.
