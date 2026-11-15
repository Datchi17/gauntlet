# lab/siem/ — Wazuh single-node + Zeek (M0)

The defensive half of the range. Built on the upstream **wazuh-docker single-node**
stack (indexer + manager + dashboard), with two Gauntlet additions layered on by
`docker-compose.override.yml`:

1. our tested detection rules are mounted into the manager (detection-as-code), and
2. **Zeek** sniffs the host-only lab segment, so *every* target — even ancient boxes
   that can't run an agent — produces network detections.

## Easiest path: let Ansible do it

```bash
cd ../ansible
cp inventory/hosts.ini.example inventory/hosts.ini     # set your host-only IPs
ansible-playbook playbooks/siem.yml                     # just the SIEM
```

That installs Docker, fetches wazuh-docker at the pinned tag, generates certs,
drops our override + `.env` in place, wires Zeek ingestion into the manager, and
brings the stack up. Dashboard: `https://<manager_ip>` (default `admin` / see the
password in the fetched `wazuh-docker/single-node/.env`).

## Manual path (if you'd rather do it by hand)

```bash
git clone --branch v4.9.2 --depth 1 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator       # certs, once
cp ../../docker-compose.override.yml .                                 # Zeek + rules
cp ../../.env.example .env && $EDITOR .env                             # set REPO_ROOT, PL_IFACE
# add the <localfile> blocks from ../../config/zeek-localfile.conf to
#   config/wazuh_cluster/wazuh_manager.conf (before </ossec_config>)
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
```

## Files
- `docker-compose.override.yml` — the Zeek service + custom-rules mount.
- `zeek/local.zeek` — JSON logging, rotation off (stable filenames for Wazuh to tail).
- `config/zeek-localfile.conf` — the `<localfile>` blocks that ingest Zeek logs.
- `.env.example` — versions, sniff interface, repo root, manager IP.

> `wazuh-docker/` and generated certs are git-ignored — they're fetched, not vendored.
