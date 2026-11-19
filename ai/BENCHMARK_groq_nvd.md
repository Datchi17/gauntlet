# Gauntlet LLM-recon benchmark

- **Model under test:** openai/gpt-oss-120b
- **Cases:** 3 × 5 run(s) = 15 scored passes
- **CVE grounding:** hand key ∪ NVD (independent)
- **Verdict:** this model **earns its place** — novel signal 5 distinct real findings vs 1.4 hallucinated/run (11% of what it cited).

| Metric | Deterministic baseline | LLM |
|---|---|---|
| Precision (grounded & correct / cited) | 90% | 89% |
| Recall (answer-key entities found) | 38% | 46% |
| **Hallucination rate** (invented / cited) | 0% | 11% |
| Entities cited | 50 | 62 |

**Novel signal** — real entities the LLM surfaced that the baseline could not (5): CVE-2011-2523, CVE-2017-7494, CVE-2018-15473, CVE-2021-41773, CVE-2021-42013

## Per-case (mean of 5 runs)

| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |
|---|---|---|---|---|
| nmap-services | 4.2 | 3.6 | 0.6 | 0.0 |
| http-recon | 6.0 | 5.2 | 0.8 | 5.0 |
| js-recon | 2.2 | 2.2 | 0.0 | 4.0 |

## Reading this

The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by construction — that gap is the LLM's opportunity (**novel signal**). The price is the **hallucination rate**: entities the LLM cited that aren't in the evidence. A useful AI layer is one whose novel signal clearly outweighs its hallucination.
