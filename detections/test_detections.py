"""
Detection-as-code tests (M1).

Two kinds of check:
  1. scorer sanity — runs without a SIEM, always on (keeps CI green from day one).
  2. live fixture replay — if a local Wazuh is installed, replay each fixture
     through wazuh-logtest and assert the mapped rule fires. Skipped otherwise,
     so the suite is green on a laptop and meaningful on the SIEM host.

Run:  python3 -m pytest -q
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "score"))

from scorer import score, load_jsonl  # noqa: E402

LOGTEST = "/var/ossec/bin/wazuh-logtest"


# ---- 1. scorer sanity (always runs) ----------------------------------------

def test_scorer_on_examples():
    actions = load_jsonl(ROOT / "score" / "examples" / "actions.jsonl")
    alerts = load_jsonl(ROOT / "score" / "examples" / "alerts.jsonl")
    res = score(actions, alerts, window=120)
    # the SSH brute force (T1110.001) and web RCE (T1190) are caught; SUID is not
    assert res["techniques"]["T1110.001"]["detected"] == 1
    assert res["techniques"]["T1548.001"]["detected"] == 0
    # the stray wazuh 5501 alert matches no action -> one false positive
    assert res["false_positives"] == 1
    assert 0.0 < res["coverage"] < 1.0


def test_brute_force_latency_is_measured():
    actions = load_jsonl(ROOT / "score" / "examples" / "actions.jsonl")
    alerts = load_jsonl(ROOT / "score" / "examples" / "alerts.jsonl")
    res = score(actions, alerts, window=120)
    assert res["mttd"] is not None and res["mttd"] >= 0


# ---- 2. live fixture replay (only on a Wazuh host) --------------------------

@pytest.mark.skipif(not shutil.which(LOGTEST) and not Path(LOGTEST).exists(),
                    reason="wazuh-logtest not installed; run on the SIEM host")
def test_ssh_bruteforce_fixture_fires_100200():
    fixture = (ROOT / "detections" / "fixtures" / "ssh_bruteforce.log").read_text()
    out = subprocess.run([LOGTEST], input=fixture, capture_output=True, text=True)
    assert "100200" in (out.stdout + out.stderr), "rule 100200 did not fire on the fixture"
