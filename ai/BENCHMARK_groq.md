# Gauntlet LLM-recon benchmark

- **Model under test:** openai/gpt-oss-120b
- **Cases:** 3 × 5 run(s) = 15 scored passes
- **Verdict:** this model **does NOT clearly earn its place** — novel signal 4 distinct real findings vs 3.0 hallucinated/run (22% of what it cited).

| Metric | Deterministic baseline | LLM |
|---|---|---|
| Precision (grounded & correct / cited) | 90% | 75% |
| Recall (answer-key entities found) | 64% | 73% |
| **Hallucination rate** (invented / cited) | 0% | 22% |
| Entities cited | 50 | 68 |

**Novel signal** — real entities the LLM surfaced that the baseline could not (4): CVE-2011-2523, CVE-2017-7494, CVE-2018-15473, CVE-2021-41773

## Per-case (mean of 5 runs)

| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |
|---|---|---|---|---|
| nmap-services | 4.2 | 3.2 | 1.0 | 0.0 |
| http-recon | 7.4 | 5.0 | 2.0 | 5.0 |
| js-recon | 2.0 | 2.0 | 0.0 | 4.0 |

## Reading this

The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by construction — that gap is the LLM's opportunity (**novel signal**). The price is the **hallucination rate**: entities the LLM cited that aren't in the evidence. A useful AI layer is one whose novel signal clearly outweighs its hallucination.
