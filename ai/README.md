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

## Free frontier-class models (no credit card)

The `api` provider works with any OpenAI-compatible endpoint, including free tiers.
Use your own free key — nothing here spends money.

```bash
# Groq (free, no card) — a big model (gpt-oss-120b; check the console for current names)
GAUNTLET_API_BASE=https://api.groq.com/openai/v1 \
GAUNTLET_API_MODEL=openai/gpt-oss-120b \
GAUNTLET_API_KEY=gsk_your_free_key \
  python3 ai/bench.py --provider api --runs 5 --out ai/BENCHMARK_groq.md

# Google Gemini (free via AI Studio, no card)
GAUNTLET_API_BASE=https://generativelanguage.googleapis.com/v1beta/openai \
GAUNTLET_API_MODEL=gemini-2.5-flash \
GAUNTLET_API_KEY=your_free_key \
  python3 ai/bench.py --provider api --out ai/BENCHMARK_gemini.md
```

Get a free Groq key at console.groq.com or a Gemini key at aistudio.google.com.
Rate limits and model names change — check the provider page. Our cases are
synthetic (public CVEs, fake endpoints), so free-tier data-use terms don't matter here.

## Independent CVE grounding — NVD (`nvd_lookup.py`)

The answer key (`valid_cves` in each case) is hand-curated. `nvd_lookup.py` lets it
be corroborated by **NIST's NVD** instead of asserted alone: it maps a case's declared
`products:` (product + version) to the CVE ids NVD associates with them, caching to
`nvd_cache.json` so the benchmark stays **offline, deterministic and CI-safe** — the
network is touched only by `--build`.

```bash
python3 ai/nvd_lookup.py --build     # refresh the cache from NVD (network, rate-limited)
python3 ai/nvd_lookup.py --audit     # hand key vs NVD, offline — corroboration + gaps
python3 ai/bench.py --provider api --nvd    # score with hand key ∪ NVD as the valid set
```

NVD keyword search matches CVE *descriptions*, so it is **recall-limited**: a CVE phrased
as "OpenSSH through 7.7" won't match a query for "7.2p2". That's why NVD **augments** the
hand key rather than replacing it — `--audit` makes the agreement and the gaps explicit.
Set `NVD_API_KEY` (free from nvd.nist.gov) to raise the rate limit from 5 to 50 req/30s.
