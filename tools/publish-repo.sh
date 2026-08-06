#!/bin/bash
# tools/publish-repo.sh — rsync the dl-build dir assembled by build-repo.sh
# (default: ../unmask-dl-build, override via UNMASK_DL_BUILD_DIR) up to
# /dl/ on unmask.sh.
#
# The canonical URL is **always unmask.sh/dl/**.  For now the single GCE VM
# (= us-central1-a) also serves /dl/.  When traffic grows, we plan to add
# nginx-side redirects to dl1.unmask.sh / dl2.unmask.sh for fan-out (= the
# client-side baseurl stays the same).
#
# usage:
#   ./tools/publish-repo.sh [--dry-run]
#
# Environment variables:
#   UNMASK_DL_HOST       default: unmask.sh           (= GCE VM, ssh target)
#   UNMASK_DL_USER       default: unmask              (= dedicated user for rsync)
#   UNMASK_DL_PATH       default: /var/www/unmask.sh/dl/
#   UNMASK_SSH_KEY       default: ~/.ssh/id_ed25519
#   UNMASK_RSH           default: ssh                 (= override the transport)
#
# The defaults above are not what the dev2 build host actually uses, and
# finding that out from scratch costs an evening, so: there is no "unmask" ssh
# user on the VM and ~/.ssh/id_ed25519 does not exist there.  The working
# invocation is root over the ansible key, with sudo because only root can read
# it:
#
#   sudo -n env UNMASK_DL_USER=root \
#       UNMASK_RSH="ssh -i /home/admin/ansible-playbook/ssh/uic-common-root" \
#       tools/publish-repo.sh
#
# Ownership survives that without a chown: the build tree is apps:apps on dev2,
# apps is uid 1001 on BOTH hosts, and rsync -a preserves the numeric id -- which
# is why /var/www/unmask.sh/dl is apps-owned despite root doing the writing.
# Check with --dry-run first either way.
#   UNMASK_DL_BUILD_DIR  default: ../unmask-dl-build  (= build output of build-repo.sh)
#
# Notes:
#   - Production publish only with a GPG / RSA-signed repo.  Rebuild via
#     build-repo.sh with UNMASK_GPG_KEY_ID + UNMASK_RSA_PRIVKEY set.
#   - The GCE VM's nginx serves the LP (= /) and /dl/ from the same vhost (= unmask.sh).
#   - To move dl1.unmask.sh / dl2.unmask.sh to a separate host later,
#     override UNMASK_DL_HOST and add an nginx-side 302 redirect to /dl/.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${UNMASK_DL_BUILD_DIR:-$ROOT/../unmask-dl-build}"
HOST="${UNMASK_DL_HOST:-unmask.sh}"
USER="${UNMASK_DL_USER:-unmask}"
DEST_PATH="${UNMASK_DL_PATH:-/var/www/unmask.sh/dl/}"
SSH_KEY="${UNMASK_SSH_KEY:-$HOME/.ssh/id_ed25519}"
RSH="${UNMASK_RSH:-ssh -i $SSH_KEY}"

DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

# CHANNEL: which repo tree to publish.
#
#   stable  (default)  the published URLs -- everything EXCEPT testing/
#   testing            only <SRC>/testing/ -> <DEST>/testing/
#
# The split is not cosmetic.  This rsync runs --delete-after, so publishing
# stable from a build tree that has no testing/ in it would delete the remote
# testing tree -- taking the build away from whoever was in the middle of
# confirming a fix on it.  Each channel therefore syncs only its own subtree,
# and stable explicitly excludes the other one.
CHANNEL="${UNMASK_CHANNEL:-stable}"
case "$CHANNEL" in
    stable)
        SRC_DIR="$SRC"
        DEST_DIR="$DEST_PATH"
        CHANNEL_EXCLUDE="--exclude=testing/"
        ;;
    testing)
        SRC_DIR="$SRC/testing"
        DEST_DIR="${DEST_PATH%/}/testing/"
        CHANNEL_EXCLUDE=""
        [ -d "$SRC_DIR" ] || { echo "ERR: $SRC_DIR is missing.  Run UNMASK_CHANNEL=testing build-repo.sh first." >&2; exit 1; }
        ;;
    *) echo "publish-repo.sh: unknown UNMASK_CHANNEL '$CHANNEL' (want stable|testing)" >&2; exit 2 ;;
esac

[ -d "$SRC" ] || { echo "ERR: $SRC is missing.  Run build-repo.sh first." >&2; exit 1; }

# apk/ exclusion is now opt-in.
#   v0.1 history: build-repo.sh's apk stage was skipped on the Rocky 9 build
#     host (no apk-tools / abuild), so $SRC/apk/ was always stale.  We
#     defaulted to --exclude=apk/ so publish would not overwrite the
#     hand-curated copy on the remote with stale content.
#   v0.2 onwards: `make repo-apk` regenerates $SRC/apk/ inside an Alpine
#     container before publish, so apk/ is now safe to ship by default.
# Keep an escape hatch (UNMASK_PUBLISH_SKIP_APK=1) for emergencies where the
# Alpine container did not run and the operator wants to preserve the remote
# copy.
APK_EXCLUDE=""
if [ "${UNMASK_PUBLISH_SKIP_APK:-0}" = "1" ]; then
    echo "==> UNMASK_PUBLISH_SKIP_APK=1 -> excluding apk/ from publish (= preserve remote copy)"
    APK_EXCLUDE="--exclude=apk/"
fi

echo "==> rsync ($CHANNEL) $SRC_DIR/ -> $USER@$HOST:$DEST_DIR"
# Note: feed/ and ipgeo/ are remote-only artifacts that do not exist under
# repo/ — feed/ is produced by the feed-server cron, ipgeo/ is the GeoIP
# (DB-IP Lite) mirror that ipgeo/install.go fetches as its primary mmdb
# source.  Exclude both so --delete-after does not nuke them.
rsync -avhz $DRY \
    --delete-after \
    --exclude=feed/ \
    --exclude=ipgeo/ \
    $CHANNEL_EXCLUDE \
    $APK_EXCLUDE \
    --info=progress2 \
    --copy-unsafe-links \
    -e "$RSH -o BatchMode=yes" \
    "$SRC_DIR/" "$USER@$HOST:$DEST_DIR"

echo
echo "==> rsync complete."

if [ -n "$DRY" ]; then
    exit 0
fi

# Verify what is now being served.  A publish has broken the repository twice
# (an apk index that lost its signature; a stale version left in dist/), and
# both times every pre-publish check had passed -- they ran against the build
# tree, not against the URLs users fetch.  So the publish checks itself.
if [ "${UNMASK_SKIP_VERIFY:-0}" = "1" ]; then
    echo "==> UNMASK_SKIP_VERIFY=1 -> not verifying the published channel"
    echo "    run tools/verify-published.sh $CHANNEL by hand before telling anyone it is up"
    exit 0
fi
echo
if "$(dirname "$0")/verify-published.sh" "$CHANNEL" "https://$HOST/dl"; then
    echo "==> publish complete."
else
    rc=$?
    echo
    echo "==> PUBLISH IS LIVE BUT BROKEN -- users see the failure above, right now."
    exit "$rc"
fi
