# detections/ — detection-as-code (M1)

Every rule ships with a replayable fixture and a test that asserts it fires.
`attack-map.yaml` maps each rule to its ATT&CK technique — the key the scorer
joins on.

- `rules/ssh_bruteforce_rules.xml` — fixture #1 (T1110.001), reused from grficsv2-siem.
- `fixtures/ssh_bruteforce.log` — 5 failures/120s from one IP; must trip rule 100200.
- `test_detections.py` — scorer sanity (always) + live wazuh-logtest replay (on the SIEM host).
