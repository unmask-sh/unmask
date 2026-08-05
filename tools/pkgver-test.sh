#!/bin/sh
# tools/pkgver-test.sh — prove a testing package sorts BELOW the stable it
# precedes, in every format, using the real comparison each package manager
# uses and the version each package REALLY carries.
#
# This exists because getting it wrong fails silently.  A pre-release that sorts
# ABOVE its stable leaves whoever is testing a fix stuck on the testing channel
# with `update` reporting nothing to do -- no error, no warning, and the person
# affected is by definition the one who took the trouble to report a bug.
#
# It builds throwaway packages with nfpm and reads the version back out of them
# rather than reasoning about the string pkgver.sh printed.  nfpm rewrites what
# it is given -- `0.1.21-rc1` becomes `0.1.21~rc1` for deb and `0.1.21_rc1` for
# apk -- so a test that compares the INPUT is testing the wrong thing.  The
# first version of this file did exactly that and reported a failure that did
# not exist; a version that reported a false PASS would have shipped the trap it
# was written to prevent.
#
# Real tools throughout:
#   rpm    rpm.vercmp via `rpm --eval`
#   rpm48  CentOS 6 (rpm 4.8) has no tilde ordering, so its algorithm is
#          reimplemented -- there is no el6 rpm on the build host, and this is
#          the case nfpm's own default gets wrong
#   deb    dpkg --compare-versions
#   apk    `apk version -t` in an Alpine container, plus `-c`: a version can
#          compare correctly and still be rejected as malformed
#
# A missing tool SKIPs loudly rather than passing quietly.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
PKGVER="$ROOT/pkgver.sh"
V="${UNMASK_TEST_VERSION:-0.1.21}"
NFPM="${NFPM:-nfpm}"
fail=0
skip=0

say()   { printf '%s\n' "$*"; }
ok()    { say "  ok    $*"; }
bad()   { say "  FAIL  $*"; fail=$((fail + 1)); }
skipf() { say "  skip  $* (tool absent)"; skip=$((skip + 1)); }

command -v "$NFPM" >/dev/null 2>&1 || {
    say "SKIP: nfpm not on PATH -- cannot build the packages this test reads."
    say "      go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
    exit 0
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# build <channel> <format> -> path to the built package
build() {
    _ch=$1; _fmt=$2; _it=${3:-1}
    set -- $("$PKGVER" "$V" "$_ch" "$_fmt" "$_it")
    cat >"$WORK/n.yaml" <<EOF
name: unmask-pkgver-probe
arch: amd64
platform: linux
version: "$1"
release: "$2"
maintainer: unmask maintainers <oss@unmask.sh>
description: throwaway package used only to read back the version nfpm emits
EOF
    _out="$WORK/$_ch-$_fmt-$_it"
    mkdir -p "$_out"
    "$NFPM" pkg -f "$WORK/n.yaml" -p "$_fmt" -t "$_out/" >/dev/null 2>&1 || return 1
    ls "$_out"/* 2>/dev/null | head -1
}

# shipped <package> <format> -> the version string the package actually carries
shipped() {
    case "$2" in
        rpm) rpm -qp --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null ;;
        deb) dpkg-deb -f "$1" Version 2>/dev/null ;;
        apk)
            # .PKGINFO holds pkgver, already including the -r<rel> suffix.
            tar -xzOf "$1" .PKGINFO 2>/dev/null | sed -n 's/^pkgver = //p' | head -1
            ;;
    esac
}

say "== pkgver ordering: testing must sort below stable (version $V) =="

for fmt in rpm deb apk; do
    tp=$(build testing "$fmt") || { bad "$fmt    nfpm could not build the testing package"; continue; }
    sp=$(build stable "$fmt")  || { bad "$fmt    nfpm could not build the stable package"; continue; }
    T=$(shipped "$tp" "$fmt")
    S=$(shipped "$sp" "$fmt")
    if [ -z "$T" ] || [ -z "$S" ]; then
        skipf "$fmt    cannot read the version back out of the built package"
        continue
    fi

    case "$fmt" in
    rpm)
        if command -v rpm >/dev/null 2>&1; then
            r=$(rpm --eval "%{lua:print(rpm.vercmp(\"$T\", \"$S\"))}" 2>/dev/null || echo "?")
            [ "$r" = "-1" ] && ok "rpm    $T < $S" || bad "rpm    $T vs $S -> vercmp=$r (want -1)"
        else
            skipf "rpm    $T vs $S"
        fi
        # ...and again without tilde ordering, which is what el6 does.
        r=$(python3 - "$T" "$S" <<'PY'
import re, sys
def seg(v): return re.findall(r'[0-9]+|[a-zA-Z]+', v)
def cmp48(a, b):
    A, B = seg(a), seg(b)
    for x, y in zip(A, B):
        if x.isdigit() and y.isdigit():
            if int(x) != int(y): return -1 if int(x) < int(y) else 1
        elif x != y: return -1 if x < y else 1
    return 0 if len(A) == len(B) else (1 if len(A) > len(B) else -1)
print(cmp48(sys.argv[1], sys.argv[2]))
PY
)
        if [ "$r" = "-1" ]; then
            ok "rpm48  $T < $S  (CentOS 6)"
        else
            bad "rpm48  $T vs $S -> $r (want -1).  A tilde in the rpm VERSION does this:
        rpm 4.8 has no tilde ordering, so the pre-release parses as MORE
        segments and wins.  Put the tag in the Release field instead."
        fi
        ;;
    deb)
        if command -v dpkg >/dev/null 2>&1; then
            dpkg --compare-versions "$T" lt "$S" && ok "deb    $T < $S" || bad "deb    $T is not < $S"
        else
            skipf "deb    $T vs $S"
        fi
        ;;
    apk)
        if command -v docker >/dev/null 2>&1; then
            out=$(docker run --rm alpine:3.20 sh -c "
                apk version -c '$T' >/dev/null 2>&1 || { echo MALFORMED; exit 0; }
                apk version -t '$T' '$S'" 2>/dev/null || echo "?")
            case "$out" in
                "<") ok "apk    $T < $S" ;;
                MALFORMED) bad "apk    $T is not a valid apk version (apk version -c rejects it).
        It may still COMPARE correctly, which is how this slips through -- the
        index built from it is the thing that breaks." ;;
                *) bad "apk    $T vs $S -> '$out' (want '<')" ;;
            esac
        else
            skipf "apk    $T vs $S"
        fi
        ;;
    esac
done

# ---- successive testing rounds must climb ------------------------------
# The channel exists to go back and forth with a reporter, so round 2 has to
# reach someone already on round 1 -- and round 10 has to beat round 9, which
# only holds if the trailing digits compare as numbers rather than as text.
say ""
say "== successive testing rounds must climb (rc1 < rc2 < rc9 < rc10) =="
for fmt in rpm deb apk; do
    prev=""; prev_it=""
    for it in 1 2 9 10; do
        p=$(build testing "$fmt" "$it") || { bad "$fmt    nfpm could not build rc$it"; break; }
        cur=$(shipped "$p" "$fmt")
        [ -n "$cur" ] || { skipf "$fmt    cannot read rc$it back"; break; }
        if [ -n "$prev" ]; then
            case "$fmt" in
            rpm) command -v rpm >/dev/null 2>&1 &&
                    { r=$(rpm --eval "%{lua:print(rpm.vercmp(\"$prev\", \"$cur\"))}" 2>/dev/null)
                      [ "$r" = "-1" ] && ok "rpm    $prev < $cur" || bad "rpm    $prev vs $cur -> $r"; } ||
                    skipf "rpm    rc$prev_it vs rc$it" ;;
            deb) command -v dpkg >/dev/null 2>&1 &&
                    { dpkg --compare-versions "$prev" lt "$cur" && ok "deb    $prev < $cur" || bad "deb    $prev is not < $cur"; } ||
                    skipf "deb    rc$prev_it vs rc$it" ;;
            apk) command -v docker >/dev/null 2>&1 &&
                    { o=$(docker run --rm alpine:3.20 apk version -t "$prev" "$cur" 2>/dev/null)
                      [ "$o" = "<" ] && ok "apk    $prev < $cur" || bad "apk    $prev vs $cur -> '$o'"; } ||
                    skipf "apk    rc$prev_it vs rc$it" ;;
            esac
        fi
        prev=$cur; prev_it=$it
    done
done

say ""
if [ "$fail" -gt 0 ]; then
    say "FAILED: $fail check(s).  Publishing a testing channel with this would strand"
    say "every user who installs from it -- update would report nothing to do."
    exit 1
fi
if [ "$skip" -gt 0 ]; then
    say "passed, $skip skipped"
else
    say "all checks passed"
fi
exit 0
