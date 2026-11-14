# lab/ansible/ — provisioning (M0)

One command stands up the range. Three playbooks, composed by `site.yml`:

| Playbook | Target | What it does |
|---|---|---|
| `playbooks/siem.yml` | this Kali host | Docker + wazuh-docker (pinned) + certs + our Zeek/rules override; brings the stack up and waits for it |
| `playbooks/built-target.yml` | `built_target` | clean Ubuntu box: pinned NTP clock, auditd, enrolled Wazuh agent |
| `playbooks/agents.yml` | `agent_targets` | best-effort agent enrollment on agent-capable VulnHub boxes (old ones skip cleanly → network-only) |

## Use

```bash
cp inventory/hosts.ini.example inventory/hosts.ini     # set host-only IPs
# adjust group_vars/all.yml if your repo path or manager IP differ
ansible-galaxy collection install ansible.posix community.general   # sysctl, etc.

ansible-playbook site.yml                 # everything
ansible-playbook playbooks/siem.yml       # just the SIEM
ansible-playbook site.yml --check         # dry run
```

## Things to set first (`group_vars/all.yml`)
- `repo_root` — where this repo lives on the SIEM host.
- `manager_ip` — this host's IP **on the host-only network**. Default vboxnet0 is
  `192.168.56.1`; PurpleLoop assumes `10.10.0.1`, so set the host-only net to match
  or change this. Agents enroll here (`:1515`) and report here (`:1514`).
- `ntp_server` — clock discipline; a trustworthy MTTD depends on it.

> Reuses the Ansible patterns from `ansible-linux-lab` (idempotent, re-runnable).
