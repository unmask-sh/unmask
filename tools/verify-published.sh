#!/bin/sh
# tools/verify-published.sh — check what is actually being served, after publish.
#
# Usage:  verify-published.sh [stable|testing] [<base url>]
#
# The release gate checks the packages before they go up.  It cannot check the
# publish itself, and the publish is what broke the repository: an apk index
# that lost its signature reached unmask.sh and made every package invisible --
# `apk add unmask` answering "no such package" -- while `make verify-packages`
# had passed minutes earlier against the previous, still-signed index.  Nothing
# looked at the result.
#
# So this reads the live URLs and installs from them, in containers, per format.
# It is the only check here that can fail because of something the publish did.
set -eu

CHANNEL="${1:-stable}"
case "$CHANNEL" in
    stable)  SUB=""; SUITE="stable" ;;
    testing) SUB="testing/"; SUITE="testing" ;;
    *) echo "verify-published.sh: unknown channel '$CHANNEL' (want stable|testing)" >&2; exit 2 ;;
esac
BASE="${2:-https://unmask.sh/dl}"
fail=0

say() { printf '%s\n' "$*"; }
ok()  { say "  ok    $*"; }
bad() { say "  FAIL  $*"; fail=$((fail + 1)); }

say "== $CHANNEL channel, as served from $BASE/$SUB =="

# ---- the signatures clients verify -------------------------------------
for u in "${SUB}rpm/x86_64/repodata/repomd.xml.asc" "${SUB}deb/dists/$SUITE/InRelease"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$BASE/$u" || echo 000)
    [ "$code" = "200" ] && ok "$u" || bad "$u -> HTTP $code (clients verify this; without it the repo is refused)"
done

# The apk index carries its signature INSIDE the tarball, so a 200 says nothing.
# An unsigned index is not a degraded repo, it is an invisible one.
#
# "could not read it" and "it has no signature" are reported apart on purpose:
# the second says the published repository is broken, and a missing gzip or a
# failed download must never be able to say that.
idx="${TMPDIR:-/tmp}/unmask-verify-apkindex.$$.tar.gz"
if ! curl -sf --max-time 30 -o "$idx" "$BASE/${SUB}apk/main/x86_64/APKINDEX.tar.gz"; then
    bad "${SUB}apk/main/x86_64/APKINDEX.tar.gz could not be fetched"
elif ! listing=$(tar -tzf "$idx" 2>/dev/null) || [ -z "$listing" ]; then
    say "  ????  ${SUB}apk/main/x86_64/APKINDEX.tar.gz downloaded but could not be listed
        (no working tar/gzip here) -- the signature was NOT checked"
elif printf '%s\n' "$listing" | grep -q '^\.SIGN\.'; then
    ok "${SUB}apk/main/x86_64/APKINDEX.tar.gz carries a .SIGN entry"
else
    bad "${SUB}apk/main/x86_64/APKINDEX.tar.gz has NO .SIGN entry -- apk will report
        UNTRUSTED and every package disappears (\`apk add unmask\` says no such package)"
fi
rm -f "$idx" 2>/dev/null || :   # cleanup must never decide the verdict

# ---- and an actual install, which is the only real proof ----------------
if ! command -v docker >/dev/null 2>&1; then
    say ""
    say "docker absent: the install checks did not run -- the signatures above are all this saw"
else

REPO_URL="$BASE/${SUB}rpm/\$basearch"
got=$(docker run --rm rockylinux:9 sh -c "
    curl -fsSL -o /tmp/k $BASE/keys/RPM-GPG-KEY-unmask 2>/dev/null && rpm --import /tmp/k
    printf '[t]\nname=t\nbaseurl=$REPO_URL\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=$BASE/keys/RPM-GPG-KEY-unmask\n' > /etc/yum.repos.d/t.repo
    dnf install -y -q unmask >/dev/null 2>&1
    rpm -q --qf '%{VERSION}-%{RELEASE}' unmask 2>/dev/null" 2>/dev/null || echo "")
[ -n "$got" ] && ok "rpm    installs from the live repo ($got)" || bad "rpm    could not install from the live repo"

got=$(docker run --rm alpine:3.20 sh -c "
    wget -qO /tmp/r.apk $BASE/${SUB}apk/unmask-release-latest.apk 2>/dev/null ||
      wget -qO /tmp/r.apk $BASE/apk/unmask-release-latest.apk 2>/dev/null
    apk add --allow-untrusted -q /tmp/r.apk >/dev/null 2>&1
    apk add -q --repository $BASE/${SUB}apk/main unmask >/dev/null 2>&1
    apk info -v 2>/dev/null | grep -m1 '^unmask-0'" 2>/dev/null || echo "")
[ -n "$got" ] && ok "apk    installs from the live repo ($got)" || bad "apk    could not install from the live repo"

fi

# ---- the container images, served from the same host as static files ----
# /v2/ answers as soon as nginx carries docker/registry/oci-static.inc; the
# tags list exists once tools/build-registry.sh output has been published.
# A missing registry is reported, not failed: an older release had none.
if [ "$CHANNEL" = stable ]; then
    reg="${BASE%%/dl*}"
    reg_host="${reg#*://}"
    hdr=$(curl -sI --max-time 20 "$reg/v2/" 2>/dev/null | tr -d '\r' | grep -i '^Docker-Distribution-API-Version:' || echo "")
    [ -n "$hdr" ] && ok "/v2/ answers as a registry" || bad "/v2/ does not answer as a registry (nginx include missing?)"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$reg/v2/admin/tags/list" || echo 000)
    if [ "$code" != "200" ]; then
        say "  ----  /v2/admin/tags/list -> HTTP $code: no images published (yet)"
    elif command -v docker >/dev/null 2>&1; then
        if got=$(docker manifest inspect "$reg_host/admin:latest" 2>/dev/null | grep -c '"digest"'); then
            ok "docker resolves $reg_host/admin:latest ($got manifest digests)"
        else
            bad "docker cannot resolve $reg_host/admin:latest (media types / headers in the include?)"
        fi
    else
        ok "/v2/admin/tags/list is served (docker absent: not pulled)"
    fi
fi

say ""
if [ "$fail" -gt 0 ]; then
    say "FAILED: $fail check(s).  The published $CHANNEL channel is broken for users right now."
    exit 1
fi
say "the $CHANNEL channel serves what it should"
