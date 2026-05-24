#!/bin/bash
# 全 10 distro の template VM (= VMID 9000-9009) を hv1 上に作成する.
# 冪等: 既存 template があれば skip.
#
# usage:
#   ./proxmox-templates.sh                     # 全 distro
#   ./proxmox-templates.sh deb13 ub2404 alpine  # 一部だけ

set -uo pipefail

HV=hv1.hsts.umic.xyz
SSH_KEY=/home/admin/ansible-playbook/ssh/uic-common-root
HV_SSH="sudo -n ssh -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

# === distro 定義 ===
# key   VMID  image                   表示名
# 共通: storage=data_ssd_t2b, bridge=vmbr1, cpu=host, dns=8.8.8.8/1.1.1.1
declare -A TPL=(
  [deb13]=9000  [deb12]=9001  [ub2604]=9002  [ub2404]=9003
  [alpine]=9004 [alma10]=9005 [alma9]=9006   [alma8]=9007
  [centos7]=9008 [centos6]=9009 [ub2204]=9010
)
declare -A IMG=(
  [deb13]=debian-13.qcow2   [deb12]=debian-12.qcow2
  [ub2604]=ubuntu-2604.img  [ub2404]=ubuntu-2404.img
  [ub2204]=ubuntu-2204.img
  [alpine]=alpine-3.23.qcow2
  [alma10]=almalinux-10.qcow2 [alma9]=almalinux-9.qcow2 [alma8]=almalinux-8.qcow2
  [centos7]=centos-7.qcow2  [centos6]=centos-6.qcow2
)
declare -A LABEL=(
  [deb13]="Debian 13"     [deb12]="Debian 12"
  [ub2604]="Ubuntu 26.04" [ub2404]="Ubuntu 24.04" [ub2204]="Ubuntu 22.04"
  [alpine]="Alpine 3.23"
  [alma10]="AlmaLinux 10" [alma9]="AlmaLinux 9" [alma8]="AlmaLinux 8"
  [centos7]="CentOS 7"    [centos6]="CentOS 6"
)

create_one() {
  local key=$1
  local vmid=${TPL[$key]}
  local img=${IMG[$key]}
  local label=${LABEL[$key]}
  local name="unmask-tpl-$key"

  echo "=== [$key] $label (VMID $vmid) ==="

  $HV_SSH root@$HV "
    set -e
    if qm status $vmid >/dev/null 2>&1; then
      cfg=\$(qm config $vmid)
      if echo \"\$cfg\" | grep -q '^template: 1'; then
        echo '[$key] template already exists, skipping'
        exit 0
      else
        echo '[$key] VM $vmid exists but is NOT a template — destroy first'
        qm stop $vmid 2>/dev/null || true
        sleep 2
        qm destroy $vmid --purge 1
      fi
    fi

    qm create $vmid \\
      --name $name \\
      --memory 2048 --cores 2 \\
      --cpu host \\
      --net0 virtio,bridge=vmbr1 \\
      --serial0 socket --vga serial0 \\
      --agent enabled=1 \\
      --ostype l26

    qm importdisk $vmid /var/lib/vz/template/iso/cloud/$img data_ssd_t2b

    qm set $vmid --scsihw virtio-scsi-pci --scsi0 data_ssd_t2b:vm-$vmid-disk-0
    qm set $vmid --boot c --bootdisk scsi0
    qm set $vmid --ide2 data_ssd_t2b:cloudinit
    qm set $vmid --ciuser root --sshkeys /root/uic-common-root.pub
    qm set $vmid --ipconfig0 ip=dhcp
    qm set $vmid --nameserver '8.8.8.8 1.1.1.1'

    qm resize $vmid scsi0 16G

    qm template $vmid
    echo '[$key] template ready'
  "
}

keys=("$@")
if [ ${#keys[@]} -eq 0 ]; then
  keys=(deb13 deb12 ub2604 ub2404 ub2204 alpine alma10 alma9 alma8 centos7 centos6)
fi

declare -a OK FAIL
for k in "${keys[@]}"; do
  if [ -z "${TPL[$k]:-}" ]; then echo "unknown: $k"; continue; fi
  if create_one "$k"; then OK+=("$k"); else FAIL+=("$k"); fi
done

echo
echo "=== summary ==="
echo "OK   : ${OK[*]:-(none)}"
echo "FAIL : ${FAIL[*]:-(none)}"
[ ${#FAIL[@]} -eq 0 ]
