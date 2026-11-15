# Gauntlet LLM-recon benchmark

- **Model under test:** openai/gpt-oss-120b
- **Cases:** 3
- **Verdict:** this model **earns its place** — novel signal 4 vs 1 hallucinated findings (8% of what it cited).

| Metric | Deterministic baseline | LLM |
|---|---|---|
| Precision (grounded & correct / cited) | 90% | 92% |
| Recall (answer-key entities found) | 64% | 86% |
| **Hallucination rate** (invented / cited) | 0% | 8% |
| Entities cited | 10 | 13 |

**Novel signal** — real entities the LLM surfaced that the baseline could not (4): CVE-2011-2523, CVE-2017-7494, CVE-2018-15473, CVE-2021-41773

## Per-case

| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |
|---|---|---|---|---|
| nmap-services | 4 | 4 | 0 | 0 |
| http-recon | 7 | 6 | 1 | 5 |
| js-recon | 2 | 2 | 0 | 4 |

## Reading this

The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by construction — that gap is the LLM's opportunity (**novel signal**). The price is the **hallucination rate**: entities the LLM cited that aren't in the evidence. A useful AI layer is one whose novel signal clearly outweighs its hallucination.
