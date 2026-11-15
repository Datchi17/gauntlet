"""
Benchmark-harness tests (M4). Pure Python, no model — validates the scoring that
the whole benchmark rests on (grounding, true positives, hallucination).

Run:  python3 -m pytest ai/ -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

yaml = pytest.importorskip("yaml")
import bench  # noqa: E402


def load(name):
    return yaml.safe_load((HERE / "cases" / name).read_text())


def test_entities_filters_tcp_tokens():
    _, eps = bench.entities("22/tcp open  80/tcp open  Apache 2.4.49")
    assert "/tcp" not in eps


def test_entities_extracts_cve_and_endpoint():
    cves, eps = bench.entities("see CVE-2021-41773 at /admin/panel")
    assert cves == {"CVE-2021-41773"}
    assert "/admin/panel" in eps


def test_scoring_counts_tp_and_hallucination():
    case = load("02_http_recon.yaml")
    # 2 real endpoints (grounded+truth), 1 invented endpoint, 1 valid CVE, 1 fabricated CVE
    llm = ("Findings: /admin and /login.php exist; CVE-2021-41773 applies. "
           "Also /wp-admin/ is present and CVE-2099-99999 affects it.")
    r = bench.score_case(case, llm)["llm"]
    assert r["tp"] == 3          # /admin, /login.php, CVE-2021-41773
    assert r["halluc"] == 2      # /wp-admin (not in evidence) + CVE-2099-99999 (not real)


def test_baseline_is_grounded_zero_hallucination():
    case = load("02_http_recon.yaml")
    r = bench.score_case(case, "")   # empty LLM output; inspect the baseline
    assert r["base"]["halluc"] == 0
    assert r["base"]["tp"] >= 4      # extracts the robots.txt / link endpoints


def test_render_smoke():
    case = load("01_nmap_services.yaml")
    rows = [bench.score_case(case, "CVE-2021-41773 and a fake CVE-2099-99999")]
    md = bench.render(rows, "test-model")
    assert "Hallucination rate" in md and "Novel signal" in md
