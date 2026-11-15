#!/usr/bin/env bash
# Import a VulnHub box into VirtualBox and take the 'clean' snapshot Gauntlet
# reverts to between runs. This is Gauntlet's "rebuild" button for pre-built
# images: the OS is not built from code, so reproducibility = archive + this script.
#
# Usage: ./import-vulnhub.sh <name> <path-to-.ova>
#   e.g. ./import-vulnhub.sh dc-1 "$HOME/Downloads/Test Machines/DC-1.ova"
#
# For .zip/.rar/.7z archives, extract the .ova/.vmx first, then point here.
set -euo pipefail

NAME="${1:?usage: import-vulnhub.sh <name> <path-to-ova>}"
OVA="${2:?usage: import-vulnhub.sh <name> <path-to-ova>}"
NET="${PL_HOSTONLY:-vboxnet0}"   # host-only network; all targets live here

[ -f "$OVA" ] || { echo "no such file: $OVA" >&2; exit 1; }

echo "[*] importing $NAME from $OVA"
VBoxManage import "$OVA" --vsys 0 --vmname "$NAME"

echo "[*] attaching NIC1 to host-only $NET (isolated lab network)"
VBoxManage modifyvm "$NAME" --nic1 hostonly --hostonlyadapter1 "$NET"

echo "[*] taking 'clean' snapshot"
VBoxManage snapshot "$NAME" take clean --description "pristine Gauntlet state"

echo "[+] $NAME ready. Revert anytime with: ./revert.sh $NAME"
