#!/bin/sh
# tools/repoconf-test.sh — install unmask-release in a container and check the
# repository configuration it writes actually parses.
#
# The postinstall builds those files with unquoted heredocs, so anything the
# shell expands inside one lands in the file.  A backtick in a COMMENT is
# enough: `dnf update` inside an explanatory line ran dnf and pasted its output
# -- package lists, progress bars, "Dependencies resolved." -- into the middle
# of /etc/yum.repos.d/unmask.repo.  dnf then refused the whole file:
#
#     Warning: failed loading '/etc/yum.repos.d/unmask.repo', skipping.
#
# Not the testing section -- the WHOLE file, including the stable repo.  So
# `dnf install unmask` stops working for everyone, and the package that broke it
# installs without an error of its own.  Nothing else in the build would have
# noticed: the rpm is valid, the file exists, and it looks right until a parser
# reads it.
#
# Checks per family: the release package installs, the config parses, the stable
# repo is enabled, and the testing repo is present but not.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${DIST:-$ROOT/dist}"
V="${UNMASK_TEST_VERSION:-}"
fail=0

say() { printf '%s\n' "$*"; }

command -v docker >/dev/null 2>&1 || { say "SKIP: docker not on PATH"; exit 0; }

# Find the release packages to test.  Newest of each format.
find_one() { ls -1 "$DIST"/unmask-release*"$1" 2>/dev/null | sort -V | tail -1; }
RPM=$(find_one ".noarch.rpm")
DEB=$(find_one "_all.deb")
APK=$(find_one "_noarch.apk")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for f in "$RPM" "$DEB" "$APK"; do [ -n "$f" ] && cp "$f" "$WORK/"; done

say "== unmask-release must write a repo config that parses =="

# ---- rpm family ----------------------------------------------------------
if [ -n "$RPM" ]; then
    out=$(docker run --rm -v "$WORK:/w:ro" rockylinux:9 sh -c '
        rpm -Uvh --quiet /w/'"$(basename "$RPM")"' >/dev/null 2>&1 || { echo INSTALL_FAILED; exit 0; }
        f=/etc/yum.repos.d/unmask.repo
        [ -f "$f" ] || { echo NO_FILE; exit 0; }
        # dnf itself is the authority on whether it can read the file.
        dnf repolist --all 2>&1 | grep -q "failed loading" && { echo DNF_REJECTED; exit 0; }
        python3 - "$f" <<PY 2>/dev/null || echo PARSE_FAILED
import configparser, sys
c = configparser.ConfigParser()
c.read(sys.argv[1])
assert c.get("unmask", "enabled") == "1", "stable repo not enabled"
assert c.get("unmask-testing", "enabled") == "0", "testing repo not disabled"
print("OK")
PY
' 2>/dev/null || echo ERROR)
    case "$out" in
        *OK*) say "  ok    rpm    unmask enabled, unmask-testing present and disabled" ;;
        *DNF_REJECTED*) say "  FAIL  rpm    dnf refuses the file -- the STABLE repo is gone too, not just testing"; fail=$((fail+1)) ;;
        *) say "  FAIL  rpm    $out"; fail=$((fail+1)) ;;
    esac
else
    say "  skip  rpm    no unmask-release rpm in $DIST"
fi

# ---- deb family ----------------------------------------------------------
if [ -n "$DEB" ]; then
    out=$(docker run --rm -v "$WORK:/w:ro" debian:12-slim sh -c '
        apt-get install -y -qq /w/'"$(basename "$DEB")"' >/dev/null 2>&1 || dpkg -i /w/'"$(basename "$DEB")"' >/dev/null 2>&1
        f=/etc/apt/sources.list.d/unmask.sources
        t=/etc/apt/sources.list.d/unmask-testing.sources
        [ -f "$f" ] && [ -f "$t" ] || { echo NO_FILE; exit 0; }
        grep -q "^Suites: stable"  "$f" || { echo BAD_STABLE; exit 0; }
        grep -q "^Suites: testing" "$t" || { echo BAD_TESTING; exit 0; }
        grep -q "^Pin-Priority: 100" /etc/apt/preferences.d/unmask-testing.pref || { echo NO_PIN; exit 0; }
        # apt is the authority: a malformed sources file makes update fail.
        apt-get update -qq 2>&1 | grep -qiE "malformed|parse" && { echo APT_REJECTED; exit 0; }
        echo OK
' 2>/dev/null || echo ERROR)
    case "$out" in
        *OK*) say "  ok    deb    both suites written, testing pinned to 100" ;;
        *) say "  FAIL  deb    $out"; fail=$((fail+1)) ;;
    esac
else
    say "  skip  deb    no unmask-release deb in $DIST"
fi

# ---- apk family ----------------------------------------------------------
if [ -n "$APK" ]; then
    out=$(docker run --rm -v "$WORK:/w:ro" alpine:3.20 sh -c '
        apk add --allow-untrusted -q /w/'"$(basename "$APK")"' >/dev/null 2>&1 || { echo INSTALL_FAILED; exit 0; }
        grep -q "^https://unmask.sh/dl/apk/main$" /etc/apk/repositories || { echo NO_STABLE_LINE; exit 0; }
        # The pre-release note must stay a comment: a live line here would make
        # `apk upgrade` start pulling pre-releases.
        grep -q "^https://unmask.sh/dl/testing" /etc/apk/repositories && { echo TESTING_IS_LIVE; exit 0; }
        apk update -q >/dev/null 2>&1 || { echo APK_REJECTED; exit 0; }
        echo OK
' 2>/dev/null || echo ERROR)
    case "$out" in
        *OK*) say "  ok    apk    stable line live, testing left as a comment" ;;
        *TESTING_IS_LIVE*) say "  FAIL  apk    the testing repo is an ACTIVE line -- apk upgrade would pull pre-releases"; fail=$((fail+1)) ;;
        *) say "  FAIL  apk    $out"; fail=$((fail+1)) ;;
    esac
else
    say "  skip  apk    no unmask-release apk in $DIST"
fi

say ""
if [ "$fail" -gt 0 ]; then
    say "FAILED: $fail family/families.  The release package installs cleanly and leaves"
    say "the machine unable to install unmask."
    exit 1
fi
say "all families parse"
