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

DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

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

echo "==> rsync $SRC/ -> $USER@$HOST:$DEST_PATH"
# Note: feed/ is an artifact produced on the remote side by a separate
# application (= the feed-server cron).  It does not exist under repo/, so
# exclude it so --delete-after does not nuke it.
rsync -avhz $DRY \
    --delete-after \
    --exclude=feed/ \
    $APK_EXCLUDE \
    --info=progress2 \
    --copy-unsafe-links \
    -e "ssh -i $SSH_KEY -o BatchMode=yes" \
    "$SRC/" "$USER@$HOST:$DEST_PATH"

echo
echo "==> publish complete."
echo "Verify (= single-path layout, in effect since 2026-05-10):"
echo "  curl -I https://$HOST/dl/keys/RPM-GPG-KEY-unmask"
echo "  curl -I https://$HOST/dl/rpm/x86_64/repodata/repomd.xml"
echo "  curl -I https://$HOST/dl/deb/dists/stable/InRelease"
echo "  curl -I https://$HOST/dl/apk/main/x86_64/APKINDEX.tar.gz"
