"""
Detection-as-code tests (M1).

Two kinds of check:
  1. scorer sanity — pure Python, always runs (keeps CI green on a laptop).
  2. catalog validation — for every `implemented` row in attack-map.yaml, replay
     its fixture through wazuh-logtest in the manager container and assert the
     mapped rule fires. Skipped automatically when Docker / the manager aren't
     here, so the suite is green on a laptop and meaningful on the SIEM host.

Run:  python3 -m pytest detections/ -q
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
DET = ROOT / "detections"
sys.path.insert(0, str(ROOT / "score"))

from scorer import score, load_jsonl  # noqa: E402


# ---- 1. scorer sanity (always runs) ----------------------------------------

def test_scorer_on_examples():
    actions = load_jsonl(ROOT / "score" / "examples" / "actions.jsonl")
    alerts = load_jsonl(ROOT / "score" / "examples" / "alerts.jsonl")
    res = score(actions, alerts, window=120)
    assert res["techniques"]["T1110.001"]["detected"] == 1
    assert res["techniques"]["T1548.001"]["detected"] == 0
    assert res["false_positives"] == 1
    assert 0.0 < res["coverage"] < 1.0


# ---- 2. catalog validation (only on a Wazuh host) --------------------------

def _manager_container() -> str | None:
    if not shutil.which("docker"):
        return None
    out = subprocess.run(
        ["docker", "ps", "--filter", "name=wazuh.manager", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    names = out.stdout.split()
    return names[0] if names else None


def _implemented_rows():
    if yaml is None:
        return []
    amap = yaml.safe_load((DET / "attack-map.yaml").read_text())
    rows = []
    for c in amap.get("coverage", []):
        if c.get("status") == "implemented" and c.get("fixture") and c.get("rule_ids"):
            rows.append(pytest.param(c, id=f"{c['rule_ids'][0]}-{c['technique']}"))
    return rows


MGR = _manager_container()


@pytest.mark.skipif(MGR is None, reason="no running wazuh.manager container (run on the SIEM host)")
@pytest.mark.parametrize("row", _implemented_rows())
def test_detection_fires(row):
    fixture = DET / row["fixture"]
    assert fixture.exists(), f"missing fixture {fixture}"
    expect = str(row["rule_ids"][0])
    r = subprocess.run(
        ["docker", "exec", "-i", MGR, "/var/ossec/bin/wazuh-logtest"],
        input=fixture.read_text(), capture_output=True, text=True,
    )
    out = r.stdout + r.stderr
    assert f"id: '{expect}'" in out, (
        f"rule {expect} ({row['name']}) did NOT fire on {row['fixture']}\n"
        f"--- logtest output tail ---\n{out[-800:]}"
    )
