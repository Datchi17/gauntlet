#!/usr/bin/env bash
# Reset a target to its pristine 'clean' snapshot (fast, no re-import).
# Usage: ./revert.sh <name>   |   ./revert.sh --all
set -euo pipefail

revert_one() {
  local n="$1"
  echo "[*] reverting $n -> clean"
  VBoxManage controlvm "$n" poweroff 2>/dev/null || true
  VBoxManage snapshot "$n" restore clean
}

if [ "${1:-}" = "--all" ]; then
  for n in $(VBoxManage list vms | sed -E 's/^"([^"]+)".*/\1/'); do revert_one "$n"; done
else
  revert_one "${1:?usage: revert.sh <name>|--all}"
fi
echo "[+] done"
