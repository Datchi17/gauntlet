# lab/ — the range (M0)

Mixed VM lab on a host-only network (not Docker-only), because the targets are
VulnHub VMs you already have.

- `targets/boxes.yaml` — the starter box inventory (name, IP, agent?, chain).
- `targets/import-vulnhub.sh` — import a box, attach host-only NIC, snapshot `clean`.
- `targets/revert.sh` — reset a box (or `--all`) to the `clean` snapshot between runs.
- `siem/` — Wazuh single-node + Zeek (TODO M0).
- `ansible/` — provision the SIEM + one built Ubuntu target, pin NTP, push agents
  (reuse `ansible-linux-lab`) (TODO M0).

First M0 task: import DC-1 and Basic Pentesting 1, stand up the SIEM, confirm it
receives Zeek events + agent logs.
