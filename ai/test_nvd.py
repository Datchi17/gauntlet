"""NVD-grounding tests (M4). No network — validates the cache/offline contract
that keeps the benchmark reproducible. Run: python3 -m pytest ai/ -q"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import nvd_lookup  # noqa: E402


def test_offline_miss_returns_empty():
    # a product not in the cache must not hit the network — empty set, offline
    r = nvd_lookup.lookup("nothing-here", "0.0", cache={})
    assert r["cves"] == [] and r["source"] == "offline-miss"


def test_cache_hit_is_used():
    cache = {"vsftpd 2.3.4": {"query": "vsftpd 2.3.4", "cves": ["CVE-2011-2523"]}}
    r = nvd_lookup.lookup("vsftpd", "2.3.4", cache=cache)
    assert r["cves"] == ["CVE-2011-2523"]


def test_cves_for_case_unions_products():
    cache = {
        "apache 2.4.49": {"cves": ["CVE-2021-41773", "CVE-2021-42013"]},
        "php 5.6.40": {"cves": ["CVE-2019-11043"]},
    }
    case = {"products": [{"product": "Apache", "version": "2.4.49"},
                         {"product": "PHP", "version": "5.6.40"}]}
    got = nvd_lookup.cves_for_case(case, cache)
    assert got == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2019-11043"}


def test_nvd_grounding_rescues_a_cited_cve():
    # a CVE not in the hand key but confirmed by NVD should score as a true positive
    import bench
    case = {"id": "t", "artifact": "Apache 2.4.49", "truth": {"valid_cves": []}}
    r = bench.score_case(case, "CVE-2021-42013 applies",
                         extra_valid_cves={"CVE-2021-42013"})["llm"]
    assert r["tp"] == 1 and r["halluc"] == 0
