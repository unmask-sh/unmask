#!/bin/bash
# tools/release-run.sh -- the release, as stages with checkpoints.
#
# What used to be a dozen manual steps with a dozen known traps (the arm64
# web packages forgotten, checksums hashed before the rpms were signed, the
# passphrase pasted into a chat, a registry temp dir left behind as root, a
# dist/ never archived) is one script that runs each stage once, records it,
# and refuses to go on when a stage did not finish.  Every stage can be
# re-run on its own; `all` runs them in order.
#
#   tools/release-run.sh <version> all --notes-file NOTES
#   tools/release-run.sh <version> <stage>            # one stage
#   tools/release-run.sh <version> status             # what is done
#
# Stages, in order:
#   preflight  main is clean and pushed, CI is green for HEAD, the embedded
#              IP-range snapshot is current, the tag does not exist yet,
#              CHANGELOG master has [Unreleased] entries, the tooling is here
#   bump       CHANGELOG master + published copy, Makefile, main.go,
#              tools/releases.json (--notes-file), commit "Release vX.Y.Z", tag
#   push       push main and the tag (explicitly -- never --tags), wait for the
#              release workflow, check the draft and the GHCR images
#   build      clean worktree at the tag, the .so caches copied in, all
#              packages for amd64 AND arm64 (27) plus the two raw binaries
#   gate       unsigned repo -> hv1 test publish -> make distro-check (5 stages)
#   sign       sign-rpm, then checksums + detached signature, then the signed
#              repository (build-repo) -- in that order
#   registry   the static OCI tree from the GHCR images (latest -> version)
#   publish    rsync to unmask.sh with its own post-publish verification
#   github     upload the packages, binaries, checksums (+ .sig) over the
#              draft's, set the body, publish as latest, verify by download
#   archive    keep dist/ (packages, binaries, checksums) under dist-archive/
#
# Not here on purpose: the fleet deploy (per host, by hand), the site docs
# rsync (which files is release-specific), the memory notes.  The script
# ends by printing what is left.
#
# Passphrase: read from ../.gpgpass (one line; the file is shredded once
# read) or UNMASK_GPG_PASSPHRASE, else prompted for.  It never appears on a
# command line or in a log.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # the checkout this script lives in
PARENT="$(dirname "$ROOT")"                        # ../ : keys, distro-verify, unmask-dl-build, CHANGELOG-master.md
DL_BUILD="${UNMASK_DL_BUILD_DIR:-$PARENT/unmask-dl-build}"
MASTER="$PARENT/CHANGELOG-master.md"
PUBLISH_CL="$PARENT/changelog-publish.sh"
GPG_KEY_ID="${UNMASK_GPG_KEY_ID:-C03DD45E28C4446FDDC48EFC34A320B544B28158}"
GNUPGHOME_DIR="${UNMASK_GNUPGHOME:-$PARENT/keys/gpg}"
SSH_KEY="${UNMASK_SSH_KEY:-/home/admin/ansible-playbook/ssh/uic-common-root}"
HV1="${UNMASK_TEST_DL_HOST:-10.8.29.1}"
REPO_SLUG="${UNMASK_GH_REPO:-unmask-sh/unmask}"
export PATH="/home/apps/go/bin:$PATH"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

VER="${1:-}"; STAGE="${2:-status}"; shift 2 2>/dev/null || shift $# 2>/dev/null || true
NOTES_FILE=""; REF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --notes-file) NOTES_FILE="$2"; shift 2 ;;
        --ref) REF="$2"; shift 2 ;;               # build from this ref instead of the tag (a rehearsal)
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 <X.Y.Z> <stage|all|status> [--notes-file F] [--ref REF]" >&2; exit 2; }
TAG="v$VER"
STATE="$DL_BUILD/release-state/$VER"
WT="$PARENT/wt-$VER"
mkdir -p "$STATE"

say()  { printf '\n==> [%s] %s\n' "$VER" "$*"; }
die()  { printf '\n!! %s\n' "$*" >&2; exit 1; }
done_mark() { date '+%F %T' > "$STATE/$1.done"; }
is_done()   { [ -f "$STATE/$1.done" ]; }
need_done() { is_done "$1" || die "stage '$1' has not finished (run: $0 $VER $1)"; }

# --- preflight ---------------------------------------------------------------
stage_preflight() {
    say "preflight"
    cd "$ROOT"
    local branch; branch=$(git branch --show-current)
    [ "$branch" = main ] || die "on branch '$branch', expected main"
    [ -z "$(git status --porcelain)" ] || die "the working tree is not clean:\n$(git status --short)"
    git fetch -q origin main
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "HEAD is not origin/main (push or pull first)"
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then die "tag $TAG already exists locally"; fi
    if git ls-remote --tags origin "refs/tags/$TAG" | grep -q .; then die "tag $TAG already exists on origin"; fi
    local sha; sha=$(git rev-parse --short HEAD)
    local ci; ci=$(gh run list -R "$REPO_SLUG" --workflow ci --limit 10 --json headSha,conclusion,status --jq ".[] | select(.headSha[0:${#sha}]==\"$sha\") | \"\(.status)/\(.conclusion)\"" | head -1)
    [ "$ci" = "completed/success" ] || die "CI for $sha is '${ci:-not found}' -- wait for green (gh run list --workflow ci)"
    say "iprange embed: checking the snapshot is current (make update-iprange-embed)"
    make -s update-iprange-embed >/dev/null 2>&1 || die "make update-iprange-embed failed"
    if [ -n "$(git status --porcelain admin/assets/iprange)" ]; then
        git status --short admin/assets/iprange
        die "the embedded IP-range snapshot changed -- review and commit it (iprange embed: refresh the snapshot before $VER), push, then run preflight again"
    fi
    [ -f "$MASTER" ] || die "CHANGELOG master not found: $MASTER"
    [ -x "$PUBLISH_CL" ] || die "changelog publisher not found: $PUBLISH_CL"
    local unreleased; unreleased=$(awk '/^## \[Unreleased\]/{p=1;next} /^## \[/{if(p)exit} p' "$MASTER" | grep -c '^- (' || true)
    [ "$unreleased" -gt 0 ] || die "CHANGELOG master has no [Unreleased] entries"
    grep -q "## \[$VER\]" "$MASTER" && die "CHANGELOG master already has a [$VER] section"
    python3 -c "import json,sys; d=json.load(open('tools/releases.json')); sys.exit(1 if any(r['version']=='$VER' for r in d['releases']) else 0)" || die "tools/releases.json already lists $VER"
    [ -d "$PARENT/keys/gpg" ] || die "keyring dir missing: $PARENT/keys/gpg"
    [ -d "$PARENT/distro-verify/e2e" ] || die "distro-verify missing: $PARENT/distro-verify"
    command -v docker >/dev/null || die "docker missing"
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
    command -v gh >/dev/null || die "gh missing"
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated"
    for d in "$ROOT"/dist/multi-modules "$ROOT"/dist/multi-modules-arm64 "$ROOT"/dist/multi-modules-openssl11 "$ROOT"/dist/multi-modules-openssl11-arm64 "$ROOT"/dist/multi-modules-openssl10 "$ROOT"/dist/multi-modules-glibc212; do
        [ "$(ls "$d" 2>/dev/null | wc -l)" -ge 14 ] || die "module cache $d is missing or short (expected 14 nginx versions); rebuild with make build-module-multi-all"
    done
    say "preflight OK: HEAD $sha on main, CI green, tag $TAG free, $unreleased unreleased entr(y|ies), caches present"
    done_mark preflight
}

# --- bump --------------------------------------------------------------------
stage_bump() {
    need_done preflight
    say "bump to $VER"
    [ -n "$NOTES_FILE" ] && [ -s "$NOTES_FILE" ] || die "--notes-file NOTES is required: one paragraph for tools/releases.json (About tab)"
    cd "$ROOT"
    local today; today=$(date '+%F')
    python3 - "$MASTER" "$VER" "$today" <<'PY'
import sys
p, ver, today = sys.argv[1:4]
s = open(p, encoding='utf-8').read()
old = '## [Unreleased]\n'
assert s.count(old) == 1
s = s.replace(old, f'## [Unreleased]\n\n## [{ver}] - {today}\n', 1)
# the [Unreleased] section is now empty: collapse the blank lines left behind
s = s.replace(f'## [Unreleased]\n\n\n## [{ver}]', f'## [Unreleased]\n\n## [{ver}]')
open(p, 'w', encoding='utf-8').write(s)
PY
    "$PUBLISH_CL" >/dev/null
    python3 - "$VER" "$today" "$NOTES_FILE" <<'PY'
import json, re, sys
ver, today, notes_file = sys.argv[1:4]
notes = open(notes_file, encoding='utf-8').read().strip().replace('\n', ' ')
for path, pat, rep in [
    ('Makefile', r'^UNMASK_VERSION \?= .*$', f'UNMASK_VERSION ?= {ver}'),
    ('admin/cmd/unmask/main.go', r'^var Version = ".*"$', f'var Version = "{ver}"'),
]:
    s = open(path, encoding='utf-8').read()
    s2, n = re.subn(pat, rep, s, count=1, flags=re.M)
    assert n == 1, path
    open(path, 'w', encoding='utf-8').write(s2)
p = 'tools/releases.json'
d = json.load(open(p, encoding='utf-8'))
d['latest'] = ver
d['releases'].insert(0, {'version': ver, 'date': today, 'notes': notes})
with open(p, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2, ensure_ascii=False); f.write('\n')
PY
    git add CHANGELOG.md Makefile admin/cmd/unmask/main.go tools/releases.json
    git diff --cached --stat
    UNMASK_WIP_ID="${UNMASK_WIP_ID:-release}" git commit -q -m "Release $TAG"
    git tag "$TAG"
    say "committed $(git rev-parse --short HEAD) and tagged $TAG (not pushed yet)"
    done_mark bump
}

# --- push --------------------------------------------------------------------
stage_push() {
    need_done bump
    say "push main and $TAG"
    cd "$ROOT"
    git push origin main
    git push origin "$TAG"                          # explicit: never --tags
    local sha; sha=$(git rev-parse "$TAG")
    say "waiting for the release workflow on ${sha:0:8}"
    local id=""
    for _ in $(seq 1 30); do
        id=$(gh run list -R "$REPO_SLUG" --workflow release --limit 5 --json databaseId,headSha --jq ".[] | select(.headSha==\"$sha\") | .databaseId" | head -1)
        [ -n "$id" ] && break
        sleep 10
    done
    [ -n "$id" ] || die "the release workflow did not start for $TAG"
    gh run watch -R "$REPO_SLUG" "$id" --exit-status > "$STATE/push.release-run.log" 2>&1 || die "the release workflow failed (see $STATE/push.release-run.log)"
    local assets; assets=$(gh release view -R "$REPO_SLUG" "$TAG" --json isDraft,assets --jq '"\(.isDraft) \(.assets|length)"')
    [ "${assets%% *}" = "true" ] || die "expected a draft release for $TAG, got: $assets"
    say "draft release exists with ${assets#* } asset(s)"
    for img in "ghcr.io/${REPO_SLUG%%/*}/admin:$VER" "ghcr.io/${REPO_SLUG%%/*}/nginx:$VER-1.28.3"; do
        docker manifest inspect "$img" >/dev/null 2>&1 || die "GHCR image missing: $img"
    done
    say "GHCR images present"
    done_mark push
}

# --- build -------------------------------------------------------------------
stage_build() {
    local ref="${REF:-$TAG}"
    [ -n "$REF" ] || need_done push
    say "build from $ref in $WT"
    cd "$ROOT"
    if [ ! -d "$WT" ]; then git worktree add "$WT" "$ref" >/dev/null; fi
    cd "$WT"
    [ "$(git rev-parse HEAD)" = "$(git rev-parse "$ref")" ] || die "$WT is not at $ref"
    [ -e keys ] || ln -s ../keys keys
    [ -e distro-verify ] || ln -s ../distro-verify distro-verify
    mkdir -p dist
    for d in "$ROOT"/dist/multi-modules*; do [ -d "dist/$(basename "$d")" ] || cp -r "$d" dist/; done
    for d in dist/multi-modules*; do [ "$(ls "$d" | wc -l)" -ge 14 ] || die "cache $d short"; done
    if ls dist/*.rpm dist/*.deb dist/*.apk >/dev/null 2>&1 && ls dist/*.rpm dist/*.deb dist/*.apk | grep -v "$VER" | grep -q .; then
        die "dist/ holds packages of another version: $(ls dist/*.rpm dist/*.deb dist/*.apk | grep -v "$VER" | head -3)"
    fi
    UNMASK_VERSION="$VER" make package package-plugin-nginx-fat package-web-nginx package-web-apache package-release > "$STATE/build.amd64.log" 2>&1 || die "amd64 build failed (see $STATE/build.amd64.log)"
    GOARCH=arm64 UNMASK_VERSION="$VER" make package package-plugin-nginx-fat package-web-nginx package-web-apache > "$STATE/build.arm64.log" 2>&1 || die "arm64 build failed (see $STATE/build.arm64.log)"
    local pkgs bins; pkgs=$(ls dist | grep -cE "\.(rpm|deb|apk)$"); bins=$(ls dist | grep -cE '^unmask-linux-(amd64|arm64)$')
    [ "$pkgs" = 27 ] && [ "$bins" = 2 ] || die "expected 27 packages + 2 binaries, got $pkgs + $bins"
    local v; v=$(./dist/unmask-linux-amd64 version 2>/dev/null | grep -v dropped | head -1)
    [[ "$v" == "unmask $VER ("* ]] || die "binary reports '$v', expected 'unmask $VER (<sha>)'"
    say "build OK: $v, 27 packages, 2 binaries"
    done_mark build
}

# --- gate --------------------------------------------------------------------
stage_gate() {
    need_done build
    say "gate: unsigned repo -> hv1 -> make distro-check"
    cd "$WT"
    sudo -n chown -R "$(id -u):$(id -g)" "$DL_BUILD/apk" 2>/dev/null || true
    ./tools/build-repo.sh "$DL_BUILD" all > "$STATE/gate.build-repo.log" 2>&1 || die "build-repo failed (see $STATE/gate.build-repo.log)"
    make repo-apk > "$STATE/gate.repo-apk.log" 2>&1 || die "repo-apk failed (see $STATE/gate.repo-apk.log)"
    UNMASK_DL_HOST="$HV1" UNMASK_DL_USER=root UNMASK_DL_PATH=/var/www/unmask-test/dl/ UNMASK_SSH_KEY="$SSH_KEY" \
        sudo -E -n bash tools/publish-repo.sh > "$STATE/gate.hv1-publish.log" 2>&1 || true   # the trailing registry rsync fails on the test host (no /v2); packages are there
    grep -q '==> rsync complete' "$STATE/gate.hv1-publish.log" || die "hv1 test publish did not complete (see $STATE/gate.hv1-publish.log)"
    curl -sf --max-time 10 "http://$HV1:8080/releases.json" | grep -q "\"latest\": *\"$VER\"" || die "hv1 does not serve $VER"
    say "running make distro-check (5 stages, 30-60 min); log: $STATE/gate.distro-check.log"
    make distro-check > "$STATE/gate.distro-check.log" 2>&1 || die "the release gate FAILED (see $STATE/gate.distro-check.log; rerun one stage with make e2e-docker / e2e-docker-mariadb / distro-verify/e2e/install-test-official.sh, then re-run this stage)"
    grep -q 'release gate PASSED' "$STATE/gate.distro-check.log" || die "gate log has no PASSED line"
    say "gate PASSED"
    done_mark gate
}

# --- sign --------------------------------------------------------------------
read_passphrase() {
    if [ -z "${UNMASK_GPG_PASSPHRASE:-}" ] && [ -s "$PARENT/.gpgpass" ]; then
        UNMASK_GPG_PASSPHRASE="$(head -n1 "$PARENT/.gpgpass")"
        shred -u "$PARENT/.gpgpass" 2>/dev/null || rm -f "$PARENT/.gpgpass"
        say "passphrase read from $PARENT/.gpgpass (file removed)"
    fi
    if [ -z "${UNMASK_GPG_PASSPHRASE:-}" ]; then
        [ -t 0 ] || die "no passphrase: put it in $PARENT/.gpgpass (one line) or export UNMASK_GPG_PASSPHRASE"
        printf 'GPG passphrase for %s: ' "$GPG_KEY_ID" >&2; stty -echo; IFS= read -r UNMASK_GPG_PASSPHRASE; stty echo; printf '\n' >&2
    fi
    export UNMASK_GPG_PASSPHRASE
}
stage_sign() {
    need_done gate
    say "sign: rpms, then checksums, then the signed repository"
    cd "$WT"
    export UNMASK_GPG_KEY_ID="$GPG_KEY_ID" UNMASK_GNUPGHOME="$GNUPGHOME_DIR" GNUPGHOME="$GNUPGHOME_DIR" LANG=C LC_ALL=C
    read_passphrase
    make sign-rpm > "$STATE/sign.rpm.log" 2>&1 || die "sign-rpm failed (see $STATE/sign.rpm.log)"
    local bad=0; for f in dist/*.rpm; do rpm -K "$f" | grep -q 'signatures OK' || { echo "  NOT signed: $f"; bad=1; }; done
    [ "$bad" = 0 ] || die "unsigned rpm(s) after sign-rpm"
    ( cd dist && rm -f checksums.txt checksums.txt.sig && sha256sum unmask-linux-* ./*.rpm ./*.deb ./*.apk > checksums.txt \
        && gpg --batch --yes -u "$GPG_KEY_ID" --detach-sign checksums.txt && gpg --verify checksums.txt.sig checksums.txt 2>&1 | grep -q 'Good signature' ) \
        || die "checksums / signature failed"
    [ "$(wc -l < dist/checksums.txt)" = 29 ] || die "checksums.txt has $(wc -l < dist/checksums.txt) lines, expected 29"
    ./tools/build-repo.sh "$DL_BUILD" all > "$STATE/sign.build-repo.log" 2>&1 || die "signed build-repo failed (see $STATE/sign.build-repo.log)"
    grep -q 'NOT signed' "$STATE/sign.build-repo.log" && die "build-repo ran unsigned (UNMASK_GPG_KEY_ID not seen)"
    gpg --verify "$DL_BUILD/rpm/x86_64/repodata/repomd.xml.asc" "$DL_BUILD/rpm/x86_64/repodata/repomd.xml" 2>&1 | grep -q 'Good signature' || die "repomd.xml.asc not good"
    gpg --verify "$DL_BUILD/deb/dists/stable/InRelease" 2>&1 | grep -q 'Good signature' || die "InRelease not good"
    cmp "$DL_BUILD/rpm/x86_64/RPMS/unmask-$VER-1.x86_64.rpm" "dist/unmask-$VER-1.x86_64.rpm" || die "repo rpm differs from the signed dist rpm"
    unset UNMASK_GPG_PASSPHRASE
    say "signed: 27 rpm OK, checksums 29 lines + .sig, repomd/InRelease good"
    done_mark sign
}

# --- registry ----------------------------------------------------------------
stage_registry() {
    need_done push
    say "registry tree from GHCR ($VER -> latest)"
    cd "$WT"
    tools/build-registry.sh "$VER" > "$STATE/registry.log" 2>&1 || true   # exit 1 = the skopeo container's root-owned temp; the tree is complete
    sudo -n rm -rf /tmp/unmask-registry.* 2>/dev/null || true
    grep -q "\"$VER\"" "$DL_BUILD/registry/v2/admin/tags/list" || die "admin tag $VER missing from the registry tree (see $STATE/registry.log)"
    cmp "$DL_BUILD/registry/v2/admin/manifests/latest.idx" "$DL_BUILD/registry/v2/admin/manifests/$VER.idx" || die "admin:latest is not $VER"
    cmp "$DL_BUILD/registry/v2/nginx/manifests/1.28.idx" "$DL_BUILD/registry/v2/nginx/manifests/$VER-1.28.3.idx" || die "nginx:1.28 is not $VER"
    say "registry OK"
    done_mark registry
}

# --- publish -----------------------------------------------------------------
stage_publish() {
    need_done sign; need_done registry
    say "publish to unmask.sh (/dl/ + /v2/) with post-publish verification"
    cd "$WT"
    UNMASK_DL_USER=root UNMASK_SSH_KEY="$SSH_KEY" sudo -n -E ./tools/publish-repo.sh > "$STATE/publish.log" 2>&1 || die "publish failed or its verification did (see $STATE/publish.log)"
    grep -q '==> publish complete' "$STATE/publish.log" || die "publish did not report completion"
    curl -sf --max-time 15 https://unmask.sh/dl/releases.json | grep -q "\"latest\": *\"$VER\"" || die "unmask.sh does not serve releases.json latest=$VER"
    say "published"
    done_mark publish
}

# --- github ------------------------------------------------------------------
stage_github() {
    need_done sign
    say "GitHub release: assets, body, publish as latest"
    cd "$WT/dist"
    gh release upload -R "$REPO_SLUG" "$TAG" unmask-linux-amd64 unmask-linux-arm64 ./*.rpm ./*.deb ./*.apk checksums.txt checksums.txt.sig --clobber > "$STATE/github.upload.log" 2>&1 || die "gh release upload failed (see $STATE/github.upload.log)"
    local prev; prev=$(gh release list -R "$REPO_SLUG" --limit 5 --json tagName --jq '.[].tagName' | grep -v "^$TAG$" | head -1)
    gh release view -R "$REPO_SLUG" "$prev" --json body --jq .body | sed -E "s|compare/v[0-9.]+\.\.\.v[0-9.]+|compare/$prev...$TAG|" > "$STATE/github.body.md"
    gh release edit -R "$REPO_SLUG" "$TAG" --notes-file "$STATE/github.body.md" --draft=false --latest >/dev/null
    local n; n=$(gh release view -R "$REPO_SLUG" "$TAG" --json isDraft,assets --jq '"\(.isDraft) \(.assets|length)"')
    [ "${n%% *}" = false ] || die "release is still a draft"
    local dl="$STATE/github.download"; rm -rf "$dl"; mkdir -p "$dl"
    gh release download -R "$REPO_SLUG" "$TAG" -p checksums.txt -p checksums.txt.sig -p "unmask-$VER-1.x86_64.rpm" -p unmask-linux-amd64 -D "$dl" >/dev/null 2>&1 || die "gh release download failed"
    cmp "$dl/checksums.txt" checksums.txt || die "published checksums.txt differs from dist"
    ( cd "$dl" && LC_ALL=C GNUPGHOME="$GNUPGHOME_DIR" gpg --verify checksums.txt.sig checksums.txt 2>&1 | grep -q 'Good signature' && LC_ALL=C sha256sum -c --ignore-missing checksums.txt | grep -q "unmask-$VER-1.x86_64.rpm: OK" ) || die "downloaded assets do not verify"
    say "GitHub release published as latest with ${n#* } assets; download verified"
    done_mark github
}

# --- archive -----------------------------------------------------------------
stage_archive() {
    need_done sign
    say "archive dist/ under $DL_BUILD/dist-archive/$TAG"
    local a="$DL_BUILD/dist-archive/$TAG"; mkdir -p "$a"
    ( cd "$WT/dist" && cp -a unmask-linux-amd64 unmask-linux-arm64 ./*.rpm ./*.deb ./*.apk checksums.txt checksums.txt.sig "$a"/ )
    ( cd "$a" && LC_ALL=C sha256sum -c checksums.txt | grep -vq ': OK$' ) && die "archive does not verify"
    say "archived $(ls "$a" | wc -l) files"
    done_mark archive
}

stage_status() {
    say "status ($STATE)"
    for s in preflight bump push build gate sign registry publish github archive; do
        if is_done "$s"; then printf '  done  %-9s %s\n' "$s" "$(cat "$STATE/$s.done")"; else printf '  --    %s\n' "$s"; fi
    done
}

finish() {
    say "release $TAG done. Left to do by hand:"
    echo "  - fleet: binary swap on the native nodes from $WT/dist/unmask-linux-amd64 (sha $(sha256sum "$WT/dist/unmask-linux-amd64" | cut -c1-8)); tool1-sg: docker compose pull + up -d --force-recreate"
    echo "  - site docs that belong to this release (rsync per file/dir, never --delete)"
    echo "  - worktree: git -C $ROOT worktree remove --force $WT (after the fleet)"
    echo "  - memory / ROADMAP notes"
}

case "$STAGE" in
    preflight|bump|push|build|gate|sign|registry|publish|github|archive|status) "stage_$STAGE" ;;
    all)
        for s in preflight bump push build gate sign registry publish github archive; do
            if is_done "$s"; then say "$s: already done ($(cat "$STATE/$s.done")), skipping"; continue; fi
            "stage_$s"
        done
        finish ;;
    *) die "unknown stage '$STAGE' (preflight|bump|push|build|gate|sign|registry|publish|github|archive|all|status)" ;;
esac
