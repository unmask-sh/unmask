#!/bin/bash
# Run the docker e2e suite on the hv1 self-hosted runner instead of dev2.
#
# WHY: dev2's working tree is shared by concurrent Claude sessions, so a
# dirty-tree `make e2e-docker` picks up their uncommitted WIP and reports FALSE
# failures (seen repeatedly on scenarios 16 / 27), and the build contends with
# active dev work.  This ships a CLEAN `git archive` of a COMMITTED tree (no WIP,
# no .git) to a dedicated VM on hv1 (Debian 13, docker + overlay2 on NVMe) and
# runs the suite there -- isolated from the shared tree + non-contending.
#
# Self-contained: NO GitHub / SaaS CI.  Code travels dev2 -> hv1 over the o-hv1
# VPN via `git archive | ssh tar -x` (the same dev2->hv1 path distro-check uses).
#
# Usage:
#   tools/e2e-on-hv1.sh                 # HEAD, full suite (make e2e-docker)
#   tools/e2e-on-hv1.sh <commit-ish>    # a specific commit
#   tools/e2e-on-hv1.sh <commit> -- 42 45   # only the named scenarios
#
# Exit code = the runner's make/run exit (number of failed scenarios), so it
# gates like a local run.
set -uo pipefail

COMMIT="HEAD"
if [ $# -gt 0 ] && [ "$1" != "--" ]; then COMMIT="$1"; shift; fi
SCN=()
if [ "${1:-}" = "--" ]; then shift; SCN=("$@"); fi

SHA=$(git rev-parse --short "$COMMIT") || { echo "bad commit: $COMMIT" >&2; exit 2; }

KEY=${UNMASK_SSH_KEY:-/home/admin/ansible-playbook/ssh/uic-common-root}
HV=${UNMASK_HV:-10.8.29.1}                 # o-hv1 (VPN address of the Proxmox host)
RUNNER_VMID=${UNMASK_RUNNER_VMID:-9200}    # unmask-e2e-runner
REMOTE_DIR=/opt/unmask-e2e

# Run a command on the Proxmox host (key is root-owned -> sudo).
hv() { sudo -n ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 root@"$HV" "$@"; }

# 1. Ensure the runner VM is up.
if [ "$(hv "qm status $RUNNER_VMID 2>/dev/null" | awk '{print $2}')" != "running" ]; then
    echo "==> starting runner VM $RUNNER_VMID"
    hv "qm start $RUNNER_VMID" >/dev/null 2>&1 || true
fi

# 2. Resolve the runner's vmbr1 IP: guest agent first, dnsmasq lease as fallback.
MAC=$(hv "qm config $RUNNER_VMID" | sed -n 's/^net0:.*virtio=\([0-9A-Fa-f:]*\).*/\1/p' | tr 'A-F' 'a-f')
RUNNER=""
for _ in $(seq 1 30); do
    RUNNER=$(hv "qm agent $RUNNER_VMID network-get-interfaces 2>/dev/null" | grep -oE '192\.168\.50\.[0-9]+' | head -1)
    if [ -z "$RUNNER" ] && [ -n "$MAC" ]; then
        RUNNER=$(hv "grep -i '$MAC' /var/lib/misc/dnsmasq*.leases 2>/dev/null" | awk '{print $3}' | tail -1)
    fi
    [ -n "$RUNNER" ] && break
    sleep 2
done
[ -z "$RUNNER" ] && { echo "could not resolve runner IP (VM $RUNNER_VMID)" >&2; exit 3; }
echo "==> runner VM $RUNNER_VMID @ $RUNNER (commit $COMMIT / $SHA)"

SSH_OPTS=(-i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15
          -o ServerAliveInterval=30 -o ServerAliveCountMax=40
          -o "ProxyCommand=sudo -n ssh -i $KEY -o BatchMode=yes -W %h:%p root@$HV")
rsh() { sudo -n ssh "${SSH_OPTS[@]}" root@"$RUNNER" "$@"; }

# 3. Ship the CLEAN committed tree (git archive -> tar); excludes WIP + .git.
echo "==> shipping clean tree to $RUNNER:$REMOTE_DIR"
git archive --format=tar "$COMMIT" | rsh "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR && tar -x -C $REMOTE_DIR"

# 4. Run the suite on the runner.
if [ ${#SCN[@]} -gt 0 ]; then
    echo "==> e2e (scenarios: ${SCN[*]}) on the runner"
    rsh "cd $REMOTE_DIR && docker compose -f e2e/docker/docker-compose.yml up -d --build --wait && \
         trap 'docker compose -f e2e/docker/docker-compose.yml down -v' EXIT && \
         BASE_URL=https://localhost:8443 ./e2e/run.sh ${SCN[*]}"
else
    echo "==> make e2e-docker on the runner"
    rsh "cd $REMOTE_DIR && make e2e-docker"
fi
