#!/usr/bin/env python3
"""NVD CVE grounding for the Gauntlet benchmark (M4).

Turns a detected product+version (e.g. "vsftpd 2.3.4") into the set of CVE IDs
that the NVD authority (NIST) associates with it — an *independent* grounding
source for the LLM-recon benchmark. Today the benchmark's answer key (each
case's `valid_cves`) is hand-asserted; this lets that key be corroborated by
NIST, and lets the scorer optionally treat an NVD-confirmed CVE as grounded.

Design (matches the rest of ai/):
  - **Stdlib only** (urllib) — no new dependency, like providers.py.
  - **Cached to ai/nvd_cache.json** (committed), so the benchmark stays offline,
    deterministic and CI-safe. The network is touched ONLY with `--build`;
    scoring and `--audit` read the cache.

NVD 2.0 API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: 5 requests / 30s without a key, 50 with one. Set NVD_API_KEY to go
faster; we sleep between calls to stay under the limit when building the cache.

CLI:
  python3 ai/nvd_lookup.py --build          # refresh the cache from NVD (network)
  python3 ai/nvd_lookup.py --audit          # hand answer-key vs NVD, offline
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# NB: yaml is imported lazily in load_cases() only — the library functions
# (lookup/cves_for_case) are stdlib-only, so importing this module never fails
# even where pyyaml is absent (e.g. CI), and its unit tests run there.

HERE = Path(__file__).resolve().parent
CACHE_PATH = HERE / "nvd_cache.json"
CASES_DIR = HERE / "cases"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVE_UP = str.upper


def _key(product: str, version: str) -> str:
    return f"{product.strip()} {version.strip()}".lower()


def load_cache() -> dict:
    try:
        return json.loads(CACHE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache: dict) -> None:
    CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def query_nvd(query: str, *, api_key: str | None = None, timeout: int = 30,
              retries: int = 3) -> list[str]:
    """Ask NVD which CVEs mention `query` (product + version). Returns sorted CVE ids.
    Keyword search matches CVE *descriptions*, so it is recall-limited by how NVD
    phrases versions (e.g. 'OpenSSH through 7.7' won't match '7.2p2') — that gap is
    exactly what --audit surfaces, and why the hand key is kept, not replaced."""
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 100})
    headers = {"User-Agent": "gauntlet-bench/1.0"}  # generic UA, no personal info
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{NVD_URL}?{params}", headers=headers)
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
            ids = {CVE_UP(v["cve"]["id"]) for v in data.get("vulnerabilities", [])}
            return sorted(ids)
        except urllib.error.HTTPError as e:
            # NVD throttles with 403/429 and flaps with 503; back off and retry
            if e.code in (403, 429, 503) and attempt < retries:
                time.sleep(6 * (attempt + 1))
                continue
            raise SystemExit(f"NVD HTTP {e.code} for {query!r}: "
                             f"{e.read().decode('utf-8', 'replace')[:300]}") from None
        except urllib.error.URLError as e:
            if attempt < retries:
                time.sleep(3 * (attempt + 1))
                continue
            raise SystemExit(f"NVD unreachable for {query!r}: {e}") from None
    return []


def lookup(product: str, version: str, *, online: bool = False,
           api_key: str | None = None, cache: dict | None = None) -> dict:
    """Resolve a product+version to its NVD CVE set, via cache. Offline by default:
    a cache miss returns an empty set so scoring never depends on the network."""
    own = cache is None
    cache = load_cache() if own else cache
    k = _key(product, version)
    if k in cache:
        return cache[k]
    if not online:
        return {"query": k, "cves": [], "source": "offline-miss"}
    cves = query_nvd(k, api_key=api_key)
    cache[k] = {"query": k, "cves": cves, "source": "nvd",
                "fetched": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if own:
        save_cache(cache)
    return cache[k]


def cves_for_case(case: dict, cache: dict | None = None) -> set[str]:
    """Union of NVD-confirmed CVEs for every product declared on a case (offline)."""
    cache = load_cache() if cache is None else cache
    out: set[str] = set()
    for p in case.get("products", []):
        out |= {CVE_UP(c) for c in lookup(p["product"], p["version"], cache=cache)["cves"]}
    return out


def load_cases(cases_dir: Path = CASES_DIR) -> list[dict]:
    try:
        import yaml
    except ImportError:
        sys.exit("needs pyyaml (pip install pyyaml)")
    return [yaml.safe_load(f.read_text()) for f in sorted(cases_dir.glob("*.yaml"))]


def build_cache(cases: list[dict], api_key: str | None = None) -> dict:
    cache = load_cache()
    pause = 1.0 if api_key else 6.5          # respect NVD's rate limit
    todo = [(p["product"], p["version"]) for c in cases for p in c.get("products", [])]
    for i, (product, version) in enumerate(todo):
        k = _key(product, version)
        entry = lookup(product, version, online=True, api_key=api_key, cache=cache)
        print(f"[*] {k}: {len(entry['cves'])} CVEs ({', '.join(entry['cves'][:4])}"
              f"{'...' if len(entry['cves']) > 4 else ''})", file=sys.stderr)
        save_cache(cache)
        if i < len(todo) - 1:
            time.sleep(pause)
    return cache


def audit(cases: list[dict]) -> int:
    """Offline: compare each case's hand-written valid_cves with what NVD confirms
    for the same products. Shows corroboration, gaps, and NVD-only candidates."""
    cache = load_cache()
    if not cache:
        print("no cache — run `python3 ai/nvd_lookup.py --build` first", file=sys.stderr)
        return 1
    print("# NVD audit of the benchmark answer key\n")
    for c in cases:
        if not c.get("products"):
            continue
        hand = {CVE_UP(x) for x in c.get("truth", {}).get("valid_cves", [])}
        nvd = cves_for_case(c, cache)
        confirmed = sorted(hand & nvd)
        hand_only = sorted(hand - nvd)     # in your key, NVD keyword-search missed it
        nvd_extra = sorted(nvd - hand)     # NVD candidates you didn't list
        print(f"## {c['id']}")
        print(f"- hand key: {len(hand)} | NVD confirms: {len(confirmed)} "
              f"-> {', '.join(confirmed) or '—'}")
        print(f"- in key but NVD keyword-search missed: {', '.join(hand_only) or '—'}")
        print(f"- NVD candidates not in key: {len(nvd_extra)}"
              + (f" (e.g. {', '.join(nvd_extra[:5])})" if nvd_extra else ""))
        print()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="NVD CVE grounding for the Gauntlet benchmark")
    p.add_argument("--build", action="store_true", help="refresh the cache from NVD (network)")
    p.add_argument("--audit", action="store_true", help="compare hand key vs NVD (offline)")
    p.add_argument("--cases", type=Path, default=CASES_DIR)
    args = p.parse_args()
    cases = load_cases(args.cases)
    if args.build:
        build_cache(cases, api_key=os.environ.get("NVD_API_KEY"))
        print(f"[+] cache written to {CACHE_PATH}", file=sys.stderr)
    if args.audit or not args.build:
        return audit(cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
