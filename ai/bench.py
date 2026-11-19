#!/usr/bin/env python3
"""
Gauntlet LLM-recon benchmark (M4) — the research payload.

Question: does an LLM add signal over deterministic recon extraction, and how
often does it hallucinate?

Each case is a recon artifact (nmap output, HTTP headers, a JS file) with a
ground-truth answer key. For the LLM and for a deterministic baseline we extract
the technical entities each one cites (CVE ids, endpoint paths) and score them
objectively against the artifact + answer key:

  - grounded    : the cited endpoint actually appears in the artifact;
                  the cited CVE is in the case's list of real applicable CVEs.
  - hallucination: a cited entity that is NOT grounded (invented).
  - true positive: a grounded entity that matches the answer key.
  - recall      : answer-key entities the analysis surfaced.
  - novel-signal: true CVEs the LLM inferred that the baseline could not (the
                  baseline only extracts what is literally present, so it cannot
                  turn "Apache 2.4.49" into CVE-2021-41773).

Usage:
  python3 ai/bench.py --provider ollama   --out ai/BENCHMARK.md
  python3 ai/bench.py --provider dry-run            # harness smoke test, no model
Stdlib + pyyaml.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import providers  # noqa: E402  (yaml imported lazily in main(), so this module
# imports cleanly without pyyaml — keeps the scorer unit tests runnable in CI)

HERE = Path(__file__).resolve().parent
PROMPT = (HERE / "prompts" / "recon_analysis.txt").read_text()

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# an endpoint path: '/' then a letter, then path chars (keeps out version strings like /2.4.49)
EP_RE = re.compile(r"/[A-Za-z][A-Za-z0-9_./-]{0,80}")


def norm_ep(e: str) -> str:
    e = e.rstrip("/")
    return e or "/"


STOP_EPS = {"/tcp", "/udp"}  # nmap "22/tcp" etc. — not endpoints


def entities(text: str) -> tuple[set[str], set[str]]:
    cves = {m.group(0).upper() for m in CVE_RE.finditer(text)}
    eps = {norm_ep(m.group(0)) for m in EP_RE.finditer(text)}
    eps = {e for e in eps if e not in STOP_EPS and len(e) >= 3}
    return cves, eps


def score_case(case: dict, llm_text: str, extra_valid_cves: set[str] | None = None) -> dict:
    artifact = case["artifact"]
    truth = case.get("truth", {})
    t_eps = {norm_ep(e) for e in truth.get("endpoints", [])}
    # grounding set = hand key ∪ optional independent source (NVD): decides what counts
    # as a REAL (not invented) CVE. The recall target stays the hand key only — the
    # *intended* findings — so NVD's hundreds of applicable CVEs don't bloat the
    # recall denominator (that was making recall read ~3% under --nvd).
    hand_cves = {c.upper() for c in truth.get("valid_cves", [])}
    grounding_cves = hand_cves | {c.upper() for c in (extra_valid_cves or set())}

    def analyse(text: str) -> dict:
        cves, eps = entities(text)
        grounded_eps = {e for e in eps if e in artifact}
        halluc_eps = eps - grounded_eps
        tp_eps = grounded_eps & t_eps
        tp_cves = cves & grounding_cves           # grounded = real/applicable (precision, novel)
        halluc_cves = cves - grounding_cves       # invented / not applicable to any version
        rec_cves = cves & hand_cves               # intended findings only (recall)
        cited = len(cves) + len(eps)
        tp = len(tp_eps) + len(tp_cves)           # grounded true positives -> precision
        rec_tp = len(tp_eps) + len(rec_cves)      # vs the hand key -> recall
        halluc = len(halluc_eps) + len(halluc_cves)
        return {
            "cited": cited, "tp": tp, "rec_tp": rec_tp, "halluc": halluc,
            "tp_eps": tp_eps, "tp_cves": tp_cves,
            "halluc_eps": halluc_eps, "halluc_cves": halluc_cves,
            "n_truth": len(t_eps) + len(hand_cves),
        }

    llm = analyse(llm_text)
    base = analyse(artifact)        # the deterministic baseline = what's literally in the recon
    # novel signal: real entities the LLM found that the baseline could not
    novel = (llm["tp_cves"] - base["tp_cves"]) | (llm["tp_eps"] - base["tp_eps"])
    return {"id": case["id"], "llm": llm, "base": base, "novel": novel}


def _rate(num: int, den: int) -> str:
    return "n/a" if den == 0 else f"{num / den * 100:.0f}%"


def aggregate(rows: list[dict], which: str) -> dict:
    cited = sum(r[which]["cited"] for r in rows)
    tp = sum(r[which]["tp"] for r in rows)
    rec_tp = sum(r[which]["rec_tp"] for r in rows)
    halluc = sum(r[which]["halluc"] for r in rows)
    truth = sum(r[which]["n_truth"] for r in rows)
    return {
        "cited": cited, "tp": tp, "halluc": halluc, "truth": truth,
        "precision": _rate(tp, cited),
        "recall": _rate(rec_tp, truth),          # recall vs the hand key (intended findings)
        "hallucination": _rate(halluc, cited),
    }


def render(rows: list[dict], provider_name: str, runs: int = 1, nvd: bool = False) -> str:
    llm = aggregate(rows, "llm")
    base = aggregate(rows, "base")
    novel = sorted({e for r in rows for e in r["novel"]})
    halluc_pct = (llm["halluc"] / llm["cited"]) if llm["cited"] else 0.0
    # novel is a union over all runs; compare against the mean hallucinations/run
    mean_halluc = llm["halluc"] / runs
    earns = len(novel) > mean_halluc and halluc_pct < 0.20
    verdict = "**earns its place**" if earns else "**does NOT clearly earn its place**"
    n_cases = len({r["id"] for r in rows})
    out = [
        "# Gauntlet LLM-recon benchmark",
        "",
        f"- **Model under test:** {provider_name}",
        f"- **Cases:** {n_cases} × {runs} run(s) = {len(rows)} scored passes",
        f"- **CVE grounding:** {'hand key ∪ NVD (independent)' if nvd else 'hand-curated answer key'}",
        f"- **Verdict:** this model {verdict} — novel signal {len(novel)} distinct real "
        f"findings vs {mean_halluc:.1f} hallucinated/run ({llm['hallucination']} of what it cited).",
        "",
        "| Metric | Deterministic baseline | LLM |",
        "|---|---|---|",
        f"| Precision (grounded & correct / cited) | {base['precision']} | {llm['precision']} |",
        f"| Recall (answer-key entities found) | {base['recall']} | {llm['recall']} |",
        f"| **Hallucination rate** (invented / cited) | {base['hallucination']} | {llm['hallucination']} |",
        f"| Entities cited | {base['cited']} | {llm['cited']} |",
        "",
        f"**Novel signal** — real entities the LLM surfaced that the baseline could not "
        f"({len(novel)}): {', '.join(novel) if novel else 'none'}",
        "",
        "## Per-case" + (f" (mean of {runs} runs)" if runs > 1 else ""),
        "",
        "| Case | LLM cited | LLM TP | LLM hallucinated | baseline TP |",
        "|---|---|---|---|---|",
    ]
    by_id: dict[str, list[dict]] = {}
    for r in rows:
        by_id.setdefault(r["id"], []).append(r)
    for cid, rs in by_id.items():
        n = len(rs)
        mean = lambda side, k: sum(x[side][k] for x in rs) / n  # noqa: E731
        out.append(f"| {cid} | {mean('llm','cited'):.1f} | {mean('llm','tp'):.1f} | "
                   f"{mean('llm','halluc'):.1f} | {mean('base','tp'):.1f} |")
    out += [
        "",
        "## Reading this",
        "",
        "The baseline cannot infer CVEs from version strings, so its CVE recall is 0 by "
        "construction — that gap is the LLM's opportunity (**novel signal**). The price is "
        "the **hallucination rate**: entities the LLM cited that aren't in the evidence. A "
        "useful AI layer is one whose novel signal clearly outweighs its hallucination.",
    ]
    return "\n".join(out) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Gauntlet LLM-recon benchmark")
    p.add_argument("--provider", default="ollama", choices=["ollama", "api", "dry-run", "replay"])
    p.add_argument("--runs", type=int, default=1, help="passes per case; metrics pooled over all runs")
    p.add_argument("--nvd", action="store_true",
                   help="also ground cited CVEs against NVD (offline, from ai/nvd_cache.json)")
    p.add_argument("--replay-file", help="for --provider replay")
    p.add_argument("--cases", type=Path, default=HERE / "cases")
    p.add_argument("--out", type=Path)
    args = p.parse_args()

    try:
        import yaml
    except ImportError:
        sys.exit("needs pyyaml (pip install pyyaml)")
    prov = providers.get(args.provider, file=args.replay_file)
    cases = [yaml.safe_load(f.read_text()) for f in sorted(args.cases.glob("*.yaml"))]
    if not cases:
        sys.exit(f"no cases in {args.cases}")

    nvd_cache = None
    if args.nvd:
        import nvd_lookup  # noqa: E402
        nvd_cache = nvd_lookup.load_cache()
        if not nvd_cache:
            sys.exit("--nvd: ai/nvd_cache.json is empty — run `python3 ai/nvd_lookup.py --build`")

    rows = []
    for c in cases:
        extra = None
        if args.nvd:
            import nvd_lookup
            extra = nvd_lookup.cves_for_case(c, nvd_cache)
        for i in range(args.runs):
            llm_text = prov.generate(PROMPT.replace("{artifact}", c["artifact"]))
            rows.append(score_case(c, llm_text, extra_valid_cves=extra))
            tag = f"{c['id']} run {i + 1}/{args.runs}" if args.runs > 1 else c["id"]
            print(f"[*] {tag}: cited={rows[-1]['llm']['cited']} "
                  f"tp={rows[-1]['llm']['tp']} halluc={rows[-1]['llm']['halluc']}", file=sys.stderr)

    report = render(rows, getattr(prov, "model", prov.name), runs=args.runs, nvd=args.nvd)
    print(report)
    if args.out:
        args.out.write_text(report)
        print(f"[+] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
