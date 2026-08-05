#!/bin/sh
# tools/pkgver.sh — the package version string for one (version, channel, format).
#
# Usage:  pkgver.sh <version> <channel> <format> [iteration]
#           version    0.1.21
#           channel    stable | testing
#           format     rpm | deb | apk
#           iteration  testing only, default 1 -- the rc number
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
# install runs 6.7.  Tilde ordering landed in rpm 4.10.0 (rpm.org ticket #56,
# fixed 2012-04); before it `~` is just a separator, so 0.1.21~rc1 parses as
# {0,1,21,rc,1} against {0,1,21} -- more segments, therefore NEWER.  An el6 box
# on a release candidate would sit there forever.
#
# Fedora forbids the tilde in Version outright, independently of el6:
#   "The tilde (~) notation which alters the way RPM does version comparisons
#    MUST NOT be used."                     -- Fedora Versioning Guidelines
# (A draft to allow it exists but is still marked "do not rely on this page".)
# The same guidelines give the form to use instead:
#   "Prerelease versions MUST use a Release: tag strictly less than 1"
#   "use a number of the form 0.N where N is an integer beginning with 1 and
#    increasing for each revision of the package"
#
# So rpm gets `Release: 0.<N>.rc<N>`, which needs no tilde and behaves
# identically on 4.8 and 4.16:  0.1.21-0.1.rc1 < 0.1.21-0.2.rc2 < 0.1.21-1.
#
# The counter leads for a reason beyond convention: with it trailing (0.rc9),
# changing the tag walks backwards -- rpm compares "beta" < "rc", so a
# hypothetical 0.beta1 would sort BELOW 0.rc9.  Leading, N always climbs
# whatever the tag says.
#
# deb and apk keep nfpm's mapping.  Both are each ecosystem's native spelling:
# Debian sorts `~` below everything, and Alpine documents alpha/beta/pre/rc as
# "earlier than the version without a suffix" (APKBUILD Reference).
#
# `~` is also wrong for apk in both senses -- 0.1.21~rc1 compares GREATER than
# 0.1.21 and `apk version -c` rejects it -- so this file is the only place that
# knows which spelling belongs where.  Nothing downstream should invent one.
set -eu

VERSION="${1:?version required}"
CHANNEL="${2:?channel required (stable|testing)}"
FORMAT="${3:?format required (rpm|deb|apk)}"
ITER="${4:-1}"

# The pre-release tag.  It CARRIES A COUNTER, and that is not cosmetic: the
# whole point of the channel is going back and forth with whoever reported a
# bug, so the second attempt has to reach them.  Republishing the same rc means
# `update` finds the version it already has and does nothing -- the reporter
# sits on the broken build believing they tested the fix, which is worse than
# having no channel at all.  Bump it for every build published to testing,
# including a rebuild of the same source.
#
# rc1 < rc2 < ... < rc9 < rc10 holds in all three formats: every one of them
# compares the trailing digits numerically rather than as text, so the tenth
# round does not fall behind the ninth.  pkgver-test.sh checks that too.
case "$CHANNEL" in
    stable) TAG="" ;;
    testing) TAG="rc${ITER}" ;;
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
        # 0.<N>.<tag> is the Fedora form -- counter first (see above).
        printf '%s 0.%s.%s\n' "$VERSION" "$ITER" "$TAG"
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
