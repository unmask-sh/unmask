#!/bin/bash
# tools/testing-run.sh -- build a pre-release and publish it to the testing
# channel: the way a fix reaches whoever reported the bug, and our own fleet,
# without a release.
#
#   tools/testing-run.sh <version> <rcN> [stage]
#     stages, in order: build  sign  publish
#     no stage = run every stage that has not finished yet
#     e.g.  tools/testing-run.sh 0.1.46 rc1
#
# The packages are <version>-0.N.rcN (rpm, deb) and <version>_rcN-r0 (apk) --
# see UNMASK_PRERELEASE in the Makefile -- so they sort above every release
# before <version> and below <version>-1 itself:
#
#   - `dnf --enablerepo=unmask-testing update 'unmask*'` installs one;
#   - a plain `dnf update` never takes a node back to the stable release,
#     which is what happened to hand-swapped binaries (a node's OS update
#     re-laid the packaged file over them);
#   - once <version> ships as <version>-1, a plain update moves to it.
#
# Nothing here reaches stable: promote-repo.sh refuses a pre-release, and the
# release run builds and gates the final.  Nothing here is gated either -- an
# rc exists to be tried by the people who asked for it.
#
# Built from a clean worktree at REF (default HEAD), which must be pushed: a
# reporter should be able to read the source of what they are running.  The
# signing passphrase comes from ../.gpgpass (one line; the file is shredded
# once read) or UNMASK_GPG_PASSPHRASE, exactly as in release-run.sh.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARENT="$(dirname "$ROOT")"
DL_BUILD="${UNMASK_DL_BUILD_DIR:-$PARENT/unmask-dl-build}"
GPG_KEY_ID="${UNMASK_GPG_KEY_ID:-C03DD45E28C4446FDDC48EFC34A320B544B28158}"
GNUPGHOME_DIR="${UNMASK_GNUPGHOME:-$PARENT/keys/gpg}"
SSH_KEY="${UNMASK_SSH_KEY:-/home/admin/ansible-playbook/ssh/uic-common-root}"
TESTING_URL="${UNMASK_TESTING_URL:-https://unmask.sh/dl/testing}"
REF="${REF:-HEAD}"

say() { printf '\n==> [%s] %s\n' "$VER-$RC" "$*"; }
die() { printf '\n!! %s\n' "$*" >&2; exit 1; }

VER="${1:-}"; RC="${2:-}"; ONLY="${3:-}"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "usage: $0 <version> <rcN> [build|sign|publish]   e.g. $0 0.1.46 rc1"
[[ "$RC" =~ ^rc[1-9][0-9]*$ ]] || die "the pre-release must be rc<N> (rc1, rc2, ...), got '$RC'"
N="${RC#rc}"
REL="0.$N.$RC"               # rpm / deb Release
APKVER="${VER}_${RC}-r0"     # apk pkgver
BINVER="$VER-$RC"            # what the binary reports

STATE="$DL_BUILD/testing-state/$VER-$RC"
WT="$PARENT/wt-$VER-$RC"
mkdir -p "$STATE"
done_mark() { date '+%F %T' > "$STATE/$1.done"; }
is_done()   { [ -f "$STATE/$1.done" ]; }
need_done() { is_done "$1" || die "stage '$1' has not finished (run: $0 $VER $RC $1)"; }

# The one mistake this channel cannot recover from is two different files under
# one NVR: a node that installed the first never upgrades to the second, and a
# reporter's "rc2 fixed it" stops meaning anything.  So an rc number is used
# once, and never below one already out.  And an rc of a version the stable
# channel already reached would sort below the release it is meant to precede.
preflight() {
    local served
    served=$(ls -1 "$DL_BUILD/testing/rpm/x86_64/RPMS/" 2>/dev/null |
        sed -nE "s/^unmask-${VER//./\\.}-0\.([0-9]+)\.rc[0-9]+\.x86_64\.rpm$/\1/p" | sort -n | tail -1)
    if [ -n "$served" ] && [ "$N" -le "$served" ]; then
        die "testing already carries $VER rc$served -- the next one is rc$((served + 1)), not $RC"
    fi
    local stable
    stable=$(ls -1 "$DL_BUILD/rpm/x86_64/RPMS/" 2>/dev/null |
        sed -nE 's/^unmask-([0-9]+\.[0-9]+\.[0-9]+)-[1-9][0-9]*\.x86_64\.rpm$/\1/p' | sort -V | tail -1)
    if [ -n "$stable" ]; then
        local newest; newest=$(printf '%s\n%s\n' "$stable" "$VER" | sort -V | tail -1)
        if [ "$stable" = "$VER" ] || [ "$newest" != "$VER" ]; then
            die "stable is already at $stable -- a pre-release of $VER would sort below it; use the next version"
        fi
    fi
}

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

stage_build() {
    preflight
    cd "$ROOT"
    git fetch -q origin 2>/dev/null || true
    local sha; sha=$(git rev-parse --verify "$REF^{commit}") || die "no such ref: $REF"
    git branch -r --contains "$sha" 2>/dev/null | grep -q 'origin/' || die "$REF ($sha) is not pushed -- push it first"
    say "build $BINVER from ${sha:0:8} in $WT"
    [ -d "$WT" ] || git worktree add -q "$WT" "$sha" || die "worktree add failed"
    cd "$WT"
    [ "$(git rev-parse HEAD)" = "$sha" ] || die "$WT is not at $sha (remove it, or build from the ref it holds)"
    [ -e keys ] || ln -s ../keys keys
    mkdir -p dist
    for d in "$ROOT"/dist/multi-modules*; do [ -d "dist/$(basename "$d")" ] || cp -r "$d" dist/; done
    for d in dist/multi-modules*; do [ "$(ls "$d" | wc -l)" -ge 14 ] || die "module cache $d is short"; done
    rm -f dist/*.rpm dist/*.deb dist/*.apk dist/unmask-linux-*
    local arch
    for arch in amd64 arm64; do
        GOARCH=$arch UNMASK_VERSION="$VER" UNMASK_PRERELEASE="$RC" \
            make package package-plugin-nginx-fat package-web-nginx package-web-apache \
            > "$STATE/build.$arch.log" 2>&1 || die "$arch build failed (see $STATE/build.$arch.log)"
    done
    local n; n=$(ls dist | grep -cE '\.(rpm|deb|apk)$')
    [ "$n" = 24 ] || die "expected 24 packages (4 x rpm/deb/apk x amd64/arm64), got $n"
    local v; v=$(./dist/unmask-linux-amd64 version 2>/dev/null | grep -v dropped | head -1)
    [[ "$v" == "unmask $BINVER ("* ]] || die "binary reports '$v', expected 'unmask $BINVER (<sha>)'"
    ls "dist/unmask-$VER-$REL.x86_64.rpm" "dist/unmask_${VER}-${REL}_amd64.deb" "dist/unmask_${APKVER}_x86_64.apk" >/dev/null 2>&1 \
        || die "package names are not in the pre-release form ($VER-$REL / $APKVER)"
    say "build OK: $v, 24 packages"
    done_mark build
}

stage_sign() {
    need_done build
    cd "$WT"
    say "sign the rpms, then index the testing channel"
    export UNMASK_GPG_KEY_ID="$GPG_KEY_ID" UNMASK_GNUPGHOME="$GNUPGHOME_DIR" GNUPGHOME="$GNUPGHOME_DIR" LANG=C LC_ALL=C
    read_passphrase
    make sign-rpm > "$STATE/sign.rpm.log" 2>&1 || die "sign-rpm failed (see $STATE/sign.rpm.log)"
    local f bad=0
    for f in dist/*.rpm; do rpm -K "$f" | grep -q 'signatures OK' || { echo "  NOT signed: $f"; bad=1; }; done
    [ "$bad" = 0 ] || die "unsigned rpm(s) after sign-rpm"
    UNMASK_CHANNEL=testing ./tools/build-repo.sh "$DL_BUILD" all > "$STATE/sign.build-repo.log" 2>&1 \
        || die "build-repo (testing) failed (see $STATE/sign.build-repo.log)"
    grep -q 'NOT signed' "$STATE/sign.build-repo.log" && die "build-repo ran unsigned (UNMASK_GPG_KEY_ID not seen)"
    gpg --verify "$DL_BUILD/testing/rpm/x86_64/repodata/repomd.xml.asc" "$DL_BUILD/testing/rpm/x86_64/repodata/repomd.xml" 2>&1 \
        | grep -q 'Good signature' || die "testing repomd.xml.asc is not good"
    unset UNMASK_GPG_PASSPHRASE
    say "signed: 12 rpm OK, testing repomd good"
    done_mark sign
}

stage_publish() {
    need_done sign
    cd "$WT"
    say "publish the testing channel"
    UNMASK_CHANNEL=testing UNMASK_DL_USER=root UNMASK_SSH_KEY="$SSH_KEY" sudo -n -E ./tools/publish-repo.sh \
        > "$STATE/publish.log" 2>&1 || die "publish failed or its verification did (see $STATE/publish.log)"
    # Read back what a client will actually be offered.
    local md primary
    md=$(curl -fsS "$TESTING_URL/rpm/x86_64/repodata/repomd.xml") || die "cannot fetch the published testing repomd"
    primary=$(printf '%s' "$md" | grep -oE 'repodata/[^"]*primary\.xml\.(gz|zst|xz)' | head -1)
    curl -fsS "$TESTING_URL/rpm/x86_64/$primary" | { zcat 2>/dev/null || cat; } \
        | grep -q "ver=\"$VER\" rel=\"$REL\"" || die "the published testing channel does not offer $VER-$REL"
    say "published: testing offers $VER-$REL"
    done_mark publish
    cat <<EOF

For the reporter, or a fleet node:
    sudo dnf --enablerepo=unmask-testing update 'unmask*'
    (apt: sudo apt install unmask=$VER-$REL    apk: unmask=$APKVER from $TESTING_URL/apk/main)

The plugin's .so is re-placed on upgrade: restart nginx afterwards, not reload.
EOF
}

case "$ONLY" in
    build|sign|publish) "stage_$ONLY" ;;
    "")
        for s in build sign publish; do is_done "$s" || "stage_$s"; done
        say "all stages done" ;;
    *) die "unknown stage '$ONLY' (build | sign | publish)" ;;
esac
