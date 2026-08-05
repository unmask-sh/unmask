#!/bin/sh
# tools/promote-repo.sh — copy a confirmed testing build into the stable tree.
#
# Usage:  promote-repo.sh [--dry-run] [<OUT_DIR>] [<version>]
#           OUT_DIR   default ../unmask-dl-build (same as build-repo.sh)
#           version   default: the newest version present in testing
#
# Then:   tools/build-repo.sh <OUT_DIR>          # reindex stable
#         tools/publish-repo.sh                  # push it
#
# The whole reason this is a copy and not a rebuild: the strongest thing that
# can be said after somebody confirms a fix is "what you confirmed is what
# shipped".  A rebuild cannot say it -- this project compiles the version into
# the binary, so the same source produces a different file once anything about
# the build differs.  So the artifact moves and nothing is renamed, which also
# means the NVR a reporter quotes identifies exactly one build forever.
#
# One honest caveat, measured rather than assumed: build-repo.sh re-signs every
# rpm when it indexes (`rpm --addsign`), and an rpm signature carries a
# timestamp, so the stable copy of an rpm is not byte-identical to the testing
# one it came from.  The PAYLOAD is -- same PAYLOADDIGEST, and extracting both
# gives no diff -- so what was confirmed is what ships; only the signature block
# differs.  deb and apk are not re-signed per index and stay byte-identical.
# The check below therefore compares payloads for rpm and bytes for the rest.
#
# Refuses to overwrite: if a file of the same name already exists in stable
# with different content, that is two different artifacts under one NVR -- one
# of them already installed somewhere -- and the fix is to publish a new
# release number, not to clobber it.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DRY=0
[ "${1:-}" = "--dry-run" ] && { DRY=1; shift; }
OUT="${1:-$ROOT/../unmask-dl-build}"
WANT="${2:-}"

SRC="$OUT/testing"
[ -d "$SRC" ] || { echo "ERR: no testing tree at $SRC" >&2; exit 1; }

# Which version to promote.  Taken from the rpm names, which carry the full
# NVR; deb and apk are matched by the same version string below.
if [ -z "$WANT" ]; then
    WANT=$(ls -1 "$SRC"/rpm/*/RPMS/unmask-[0-9]*.rpm 2>/dev/null |
        sed -E 's#.*/unmask-([0-9][^-]*-[0-9][^.]*)\..*#\1#' | sort -V | tail -1)
    [ -n "$WANT" ] || { echo "ERR: no unmask rpm found under $SRC/rpm -- nothing to promote" >&2; exit 1; }
    echo "==> promoting the newest build in testing: $WANT"
else
    echo "==> promoting $WANT"
fi

copied=0
skipped=0
conflicts=0

# same <a> <b> -> 0 when both exist and carry the same content.  For rpm that
# means the payload digest, because indexing re-signs and a signature carries a
# timestamp; for deb and apk it means the bytes.
same() {
    [ -f "$1" ] && [ -f "$2" ] || return 1
    case "$1" in
        *.rpm)
            _da=$(rpm -qp --qf '%{PAYLOADDIGEST}' "$1" 2>/dev/null)
            _db=$(rpm -qp --qf '%{PAYLOADDIGEST}' "$2" 2>/dev/null)
            [ -n "$_da" ] && [ "$_da" = "$_db" ]
            ;;
        *) cmp -s "$1" "$2" ;;
    esac
}

promote_file() { # <src file> <dest dir>
    _s=$1; _d=$2
    _n=$(basename "$_s")
    _t="$_d/$_n"
    if [ -f "$_t" ]; then
        if same "$_s" "$_t"; then
            skipped=$((skipped + 1))
            return 0
        fi
        echo "  CONFLICT $_n"
        echo "           already in stable with different content."
        echo "           Two artifacts cannot share one NVR -- publish a new release"
        echo "           number to testing instead of overwriting this."
        conflicts=$((conflicts + 1))
        return 0
    fi
    if [ "$DRY" = 1 ]; then
        echo "  would copy $_n -> ${_d#"$OUT"/}"
    else
        mkdir -p "$_d"
        cp -p "$_s" "$_t"
        # Read it back rather than trusting cp: this is the one guarantee the
        # whole channel rests on.
        if ! cmp -s "$_s" "$_t"; then
            echo "ERR: $_n differs after copy -- refusing to continue" >&2
            exit 1
        fi
        echo "  copied $_n"
    fi
    copied=$((copied + 1))
}

# rpm: per arch, everything carrying this exact NVR
for archdir in "$SRC"/rpm/*/RPMS; do
    [ -d "$archdir" ] || continue
    arch=$(basename "$(dirname "$archdir")")
    for f in "$archdir"/*-"$WANT".*.rpm; do
        [ -f "$f" ] || continue
        promote_file "$f" "$OUT/rpm/$arch/RPMS"
    done
done

# deb: pool is flat per source package; match the version between the
# underscores (unmask_0.1.21-1_amd64.deb).
DEBVER=$(printf '%s' "$WANT")
for f in "$SRC"/deb/pool/main/*/*/*_"$DEBVER"_*.deb; do
    [ -f "$f" ] || continue
    rel=${f#"$SRC"/deb/pool/}
    promote_file "$f" "$OUT/deb/pool/$(dirname "$rel")"
done

# apk: <name>-<pkgver>-r<pkgrel>.apk, and the version already carries -r<N>.
APKVER=$(printf '%s' "$WANT" | sed 's/-\([0-9][0-9]*\)$/-r\1/')
for archdir in "$SRC"/apk/main/*; do
    [ -d "$archdir" ] || continue
    arch=$(basename "$archdir")
    for f in "$archdir"/*-"$APKVER".apk; do
        [ -f "$f" ] || continue
        promote_file "$f" "$OUT/apk/main/$arch"
    done
done

echo
if [ "$conflicts" -gt 0 ]; then
    echo "REFUSED: $conflicts file(s) already exist in stable with different content."
    echo "Nothing was overwritten.  Publish a new release number to testing."
    exit 1
fi
if [ "$copied" = 0 ] && [ "$skipped" = 0 ]; then
    echo "nothing matched $WANT under $SRC -- check the version"
    exit 1
fi
echo "promoted $copied file(s), $skipped already identical in stable"
[ "$DRY" = 1 ] && echo "(dry run -- nothing written)"
echo
echo "Next:  tools/build-repo.sh $OUT        # reindex stable"
echo "       tools/publish-repo.sh           # push stable (testing is left alone)"
