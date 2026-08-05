#!/bin/sh
# tools/pkgver.sh — the package version string for one (version, channel, format).
#
# Usage:  pkgver.sh <version> <channel> <format>     # -> "<version> <release>"
#           version  0.1.21
#           channel  stable | testing
#           format   rpm | deb | apk
#
# Prints two space-separated fields to feed nfpm's `version:` and `release:`.
#
# WHY THIS IS NOT ONE STRING FOR ALL THREE
#
# A pre-release must sort BELOW the stable it precedes, or whoever is testing a
# fix can never leave the testing channel -- and they never see an error, only
# "nothing to do", which is the worst way for this to fail.  The three package
# managers do not agree on how to write that, and nfpm's own mapping gets one of
# them wrong.  Measured, not assumed (tools/pkgver-test.sh re-checks all of it):
#
#   nfpm from `version: 0.1.21-rc1` emits
#     rpm  0.1.21~rc1-1   ordering OK on rpm 4.16 -- WRONG on rpm 4.8
#     deb  0.1.21~rc1-1   ordering OK
#     apk  0.1.21_rc1-r0  ordering OK, and a valid apk version
#
# rpm 4.8 is CentOS 6, which is not a legacy tail here: the largest real
# install runs 6.7.  Tilde ordering landed in RPM 4.10 (2012); before it `~` is
# just a separator, so 0.1.21~rc1 parses as {0,1,21,rc,1} against {0,1,21} --
# more segments, therefore NEWER.  An el6 box on a release candidate would sit
# there forever.
#
# So rpm alone is overridden onto the Release field, which needs no tilde and
# behaves identically on 4.8 and 4.16:  0.1.21-0.rc1  <  0.1.21-1.
# deb and apk keep nfpm's mapping, which is already right and is each
# ecosystem's native spelling.
#
# `~` is also wrong for apk in both senses -- 0.1.21~rc1 compares GREATER than
# 0.1.21 and `apk version -c` rejects it -- so this file is the only place that
# knows which spelling belongs where.  Nothing downstream should invent one.
set -eu

VERSION="${1:?version required}"
CHANNEL="${2:?channel required (stable|testing)}"
FORMAT="${3:?format required (rpm|deb|apk)}"

# The pre-release tag.  One per channel; testing gets a fixed tag rather than a
# counter because the artifact is promoted, not renumbered -- a fix that needs a
# second round replaces rc1 in place, and the reporter's `update` still moves.
case "$CHANNEL" in
    stable) TAG="" ;;
    testing) TAG="rc1" ;;
    *) echo "pkgver.sh: unknown channel '$CHANNEL' (want stable|testing)" >&2; exit 2 ;;
esac

if [ -z "$TAG" ]; then
    # Stable: release 1 everywhere, so a pre-release Release of 0.<tag> is
    # always below it.
    printf '%s 1\n' "$VERSION"
    exit 0
fi

case "$FORMAT" in
    rpm)
        # Release, not Version: no tilde, so rpm 4.8 sorts it correctly too.
        printf '%s 0.%s\n' "$VERSION" "$TAG"
        ;;
    deb | apk)
        # nfpm's semver mapping: 0.1.21-rc1 -> deb 0.1.21~rc1, apk 0.1.21_rc1.
        printf '%s-%s 1\n' "$VERSION" "$TAG"
        ;;
    *)
        echo "pkgver.sh: unknown format '$FORMAT' (want rpm|deb|apk)" >&2
        exit 2
        ;;
esac
