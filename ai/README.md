# ai/ — LLM-recon benchmark (M4)

The research payload: does an LLM add signal over deterministic recon extraction,
and how often does it hallucinate?

Each case in `cases/` is a recon artifact (nmap output, HTTP headers, a JS file)
plus a ground-truth answer key. `bench.py` runs the model **and** a regex baseline
over each, extracts the technical entities each cites (CVE ids, endpoint paths),
and scores them objectively against the evidence:

- **hallucination** — a cited endpoint absent from the artifact, or a cited CVE not
  in the case's list of real applicable CVEs (i.e. invented).
- **novel signal** — real CVEs the LLM inferred from version strings that the
  baseline cannot produce (it only extracts what is literally present).

```bash
# local model — nothing leaves the box
GAUNTLET_OLLAMA_URL=http://<ollama-ip>:11434 python3 ai/bench.py --provider ollama --out ai/BENCHMARK.md
python3 ai/bench.py --provider dry-run     # harness smoke test, no model
python3 -m pytest ai/ -q                    # scorer tests
```

Latest run: [`BENCHMARK.md`](BENCHMARK.md). Frontier models (Claude/OpenAI) plug in
as another `providers.py` subclass behind an API key; the default stays fully local.
