# Gauntlet LLM-recon benchmark

- **Model under test:** qwen2.5-coder:3b
- **Cases:** 3
- **Verdict:** this model **does NOT clearly earn its place** — novel signal 1 vs 8 hallucinated findings (47% of what it cited).

| Metric | Deterministic baseline | LLM |
|---|---|---|
| Precision (grounded & correct / cited) | 90% | 53% |
| Recall (answer-key entities found) | 64% | 64% |
| **Hallucination rate** (invented / cited) | 0% | 47% |
| Entities cited | 10 | 17 |

**Novel signal** — real entities the LLM surfaced that the baseline could not (1): CVE-2017-7494

## Per-case

| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |
|---|---|---|---|---|
| nmap-services | 8 | 1 | 7 | 0 |
| http-recon | 6 | 5 | 1 | 5 |
| js-recon | 3 | 3 | 0 | 4 |

## Reading this

The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by construction — that gap is the LLM's opportunity (**novel signal**). The price is the **hallucination rate**: entities the LLM cited that aren't in the evidence. A useful AI layer is one whose novel signal clearly outweighs its hallucination.
