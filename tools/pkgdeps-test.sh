#!/bin/sh
# tools/pkgdeps-test.sh — prove the exact-version pin between unmask and its
# companion packages actually resolves, in every format.
#
# The .so and the daemon share the _bv / JA4 contract, so the companion
# packages pin unmask to the exact build.  That pin is spelled differently per
# packager, and two of the three include the RELEASE while one must not:
#
#   rpm   unmask = 0.1.21          release omitted -- rpm matches any release
#   deb   unmask (= 0.1.21-1)      dpkg compares the whole string
#   apk   unmask=0.1.21-r1         apk compares the whole version
#
# Getting it wrong makes the packages uninstallable together, which no unit
# test sees and which the build itself reports as success.  It happened the
# moment the release became settable: deb and apk were still pinning
# `0.1.21`, so `apt install` answered "held broken packages" and apk
# "breaks: unmask-plugin-nginx-0.1.21-r1[unmask=0.1.21]" -- against packages
# that had just built cleanly.
#
# So this installs them, in a container, per format, and checks both landed.
# Requires nfpm and docker; SKIPs loudly without them.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="${UNMASK_TEST_VERSION:-0.1.21}"
R="${UNMASK_TEST_RELEASE:-1}"
NFPM="${NFPM:-nfpm}"
fail=0

say() { printf '%s\n' "$*"; }

for t in "$NFPM" docker; do
    command -v "$t" >/dev/null 2>&1 || { say "SKIP: $t not on PATH"; exit 0; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The pins as the templates spell them, expanded the same way the Makefile does.
DEP_RPM="unmask = $V"
DEP_DEB="unmask (= $V-$R)"
DEP_APK="unmask=$V-r$R"

cat >"$WORK/core.yaml" <<EOF
name: unmask
arch: amd64
platform: linux
version: "$V"
release: "$R"
maintainer: unmask maintainers <oss@unmask.sh>
description: core (probe)
EOF
cat >"$WORK/comp.yaml" <<EOF
name: unmask-plugin-nginx
arch: amd64
platform: linux
version: "$V"
release: "$R"
maintainer: unmask maintainers <oss@unmask.sh>
description: companion (probe)
overrides:
  rpm:
    depends: ["$DEP_RPM"]
  deb:
    depends: ["$DEP_DEB"]
  apk:
    depends: ["$DEP_APK"]
EOF

for fmt in rpm deb apk; do
    "$NFPM" pkg -f "$WORK/core.yaml" -p "$fmt" -t "$WORK/" >/dev/null 2>&1
    "$NFPM" pkg -f "$WORK/comp.yaml" -p "$fmt" -t "$WORK/" >/dev/null 2>&1
done

say "== companion packages must install alongside the core they pin =="

check() { # <fmt> <image> <install cmd> <count cmd> <pin>
    _fmt=$1; _img=$2; _inst=$3; _count=$4; _pin=$5
    got=$(docker run --rm -v "$WORK:/w:ro" "$_img" sh -c \
        "cd /tmp && cp /w/*.$_fmt . 2>/dev/null; $_inst >/dev/null 2>&1; $_count" 2>/dev/null || echo 0)
    if [ "$got" = "2" ]; then
        say "  ok    $_fmt    both installed with pin: $_pin"
    else
        say "  FAIL  $_fmt    pin '$_pin' does not resolve against the built package"
        say "        installed $got of 2.  The companion pins a version string the core"
        say "        does not carry -- check whether that format needs the release."
        fail=$((fail + 1))
    fi
}

check rpm rockylinux:9 \
    "rpm -Uvh --nodigest --nosignature ./unmask-$V-$R.x86_64.rpm ./unmask-plugin-nginx-$V-$R.x86_64.rpm" \
    "rpm -qa | grep -c '^unmask'" "$DEP_RPM"
check deb debian:12-slim \
    "apt-get install -qq ./unmask_$V-${R}_amd64.deb ./unmask-plugin-nginx_$V-${R}_amd64.deb" \
    "dpkg -l unmask unmask-plugin-nginx 2>/dev/null | grep -c '^ii'" "$DEP_DEB"
check apk alpine:3.20 \
    "apk add --allow-untrusted ./unmask_$V-r${R}_x86_64.apk ./unmask-plugin-nginx_$V-r${R}_x86_64.apk" \
    "apk info 2>/dev/null | grep -c '^unmask'" "$DEP_APK"

say ""
if [ "$fail" -gt 0 ]; then
    say "FAILED: $fail format(s).  These packages build cleanly and cannot be installed."
    exit 1
fi
say "all formats resolve"
