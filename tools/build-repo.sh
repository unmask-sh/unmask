#!/bin/bash
# tools/build-repo.sh — take the rpm/deb/apk files under dist/ and assemble
# the repo layout to be published at unmask.sh:/var/www/unmask.sh/dl/ under
# repo/.
#
# usage:
#   ./tools/build-repo.sh [OUT_DIR]
#
#   OUT_DIR default: ../unmask-dl-build (= sibling of the working tree so the
#   build output stays out of the git index).  Production publish is handled
#   by a separate script (= tools/publish-repo.sh) that rsyncs to
#   unmask.sh:/var/www/unmask.sh/dl/.
#
# **Single-path design** (= unified on 2026-05-10 17:39 JST):
#   Per-distro paths are gone.  The implementation side has been
#   distro-neutral from the start thanks to the Go static binary + fat
#   plugin + nfpm overrides.  We flatten the previously complex server-side
#   paths to match reality.
#
# **merge-friendly** (= carried over from the 2026-05-09 rework):
#   No full wipe (rm -rf $OUT).  Each stage uses a
#   "regenerate if the tool is available / keep existing otherwise" path.
#   Don't have the rpm stage wipe out merged-in deb/apk metadata that
#   was generated on another host and shipped over via tgz.
#
# Output layout (= single path):
#   <OUT_DIR>/rpm/{x86_64,aarch64}/{RPMS,repodata}/
#   <OUT_DIR>/deb/dists/stable/main/binary-{amd64,arm64}/{Packages.gz,InRelease,Release.gpg}
#   <OUT_DIR>/deb/pool/main/u/unmask/*.deb
#   <OUT_DIR>/apk/main/{x86_64,aarch64}/{APKINDEX.tar.gz,*.apk}
#   <OUT_DIR>/keys/{RPM-GPG-KEY-unmask,unmask.rsa.pub}
#
# GPG / RSA signing is controlled by environment variables:
#   UNMASK_GPG_KEY_ID=oss@unmask.sh   # signing key for rpm/deb metadata
#   UNMASK_RSA_PRIVKEY=~/.abuild/...rsa  # signing key for apk index
# If unset, signing is skipped (= dry run).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
OUT="${1:-$ROOT/../unmask-dl-build}"

[ -d "$DIST" ] || { echo "ERR: $DIST not found.  Run 'make package' first." >&2; exit 1; }

# ---- Required tool detection (= graceful degradation) ----
have() { command -v "$1" >/dev/null 2>&1; }
need_or_skip() {
    if have "$1"; then echo "  [ok] $1"; return 0; fi
    echo "  [missing] $1 -> skipping the related stage (= keep existing metadata)"; return 1
}
echo "==> tool check:"
HAVE_CREATEREPO=0; have createrepo_c   && HAVE_CREATEREPO=1; need_or_skip createrepo_c   || true
HAVE_APT=0;        have apt-ftparchive && HAVE_APT=1;        need_or_skip apt-ftparchive || true
HAVE_APK=0;        have apk            && HAVE_APK=1;        need_or_skip apk            || true
have gpg          && echo "  [ok] gpg (= optional signing)"
have abuild-sign  && echo "  [ok] abuild-sign (= optional apk signing)"
echo

echo "==> output: $OUT"
mkdir -p "$OUT"/{rpm,deb,apk,keys}

# ---- keys (= always overwrite with the latest public key. idempotent because the files are small) ----
cp "$ROOT/rpm/release/RPM-GPG-KEY-unmask" "$OUT/keys/RPM-GPG-KEY-unmask"
cp "$ROOT/rpm/release/unmask.rsa.pub"      "$OUT/keys/unmask.rsa.pub"

# ============================================================
# rpm stage (= regenerate if createrepo_c is present; otherwise leave the existing tree)
# ============================================================
if [ "$HAVE_CREATEREPO" = 1 ]; then
    echo "==> rpm stage: regenerate (= single path)"
    rm -rf "$OUT/rpm"
    mkdir -p "$OUT/rpm"

    # Place the corresponding rpms per arch.  noarch (= unmask-release etc.)
    # goes into every arch dir.
    for arch in x86_64 aarch64; do
        arch_dir="$OUT/rpm/$arch/RPMS"
        mkdir -p "$arch_dir"
        # per-arch rpms
        for f in "$DIST"/*."$arch".rpm; do
            [ -f "$f" ] && cp "$f" "$arch_dir"/
        done
        # noarch (= unmask-release etc.)
        for f in "$DIST"/*.noarch.rpm; do
            [ -f "$f" ] && cp "$f" "$arch_dir"/
        done
    done

    # generate repodata
    for arch in x86_64 aarch64; do
        arch_dir="$OUT/rpm/$arch"
        [ -d "$arch_dir/RPMS" ] || continue
        echo "  -> createrepo_c $arch_dir"
        createrepo_c --quiet "$arch_dir"
        # GPG sign (= optional)
        if [ -n "${UNMASK_GPG_KEY_ID:-}" ]; then
            gpg --batch --yes --default-key "$UNMASK_GPG_KEY_ID" \
                --detach-sign --armor "$arch_dir/repodata/repomd.xml"
        fi
    done
else
    echo "==> rpm stage: skip (= createrepo_c absent / keeping existing $OUT/rpm)"
fi

# ============================================================
# deb stage (= regenerate if apt-ftparchive is present; otherwise keep existing)
# ============================================================
if [ "$HAVE_APT" = 1 ]; then
    echo "==> deb stage: regenerate (= single path / Suites: stable)"
    rm -rf "$OUT/deb"
    mkdir -p "$OUT/deb"

    POOL="$OUT/deb/pool/main/u/unmask"
    mkdir -p "$POOL"
    cp "$DIST"/*.deb "$POOL"/ 2>/dev/null || true

    DSTABLE="$OUT/deb/dists/stable"
    for arch in amd64 arm64; do
        bin="$DSTABLE/main/binary-$arch"
        mkdir -p "$bin"
        ( cd "$OUT/deb" && apt-ftparchive --arch "$arch" packages "pool/main" ) > "$bin/Packages"
        gzip -kf "$bin/Packages"
    done

    cat > "$DSTABLE/Release" <<RELEASE
Origin: unmask
Label: unmask
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: unmask package repository (single-path / distro-neutral)
Date: $(date -Ru)
RELEASE
    if [ -n "${UNMASK_GPG_KEY_ID:-}" ]; then
        gpg --batch --yes --default-key "$UNMASK_GPG_KEY_ID" \
            --clearsign -o "$DSTABLE/InRelease" "$DSTABLE/Release"
        gpg --batch --yes --default-key "$UNMASK_GPG_KEY_ID" \
            --detach-sign --armor -o "$DSTABLE/Release.gpg" "$DSTABLE/Release"
    fi
else
    echo "==> deb stage: skip (= apt-ftparchive absent / keeping existing $OUT/deb)"
fi

# ============================================================
# apk stage (= regenerate if apk is present; otherwise keep existing)
# ============================================================
if [ "$HAVE_APK" = 1 ]; then
    echo "==> apk stage: regenerate (= single path / main 1 channel)"
    rm -rf "$OUT/apk"
    mkdir -p "$OUT/apk"

    for arch in x86_64 aarch64; do
        d="$OUT/apk/main/$arch"
        mkdir -p "$d"
        # per-arch apks + noarch (= unmask-release)
        for f in "$DIST"/*_"$arch".apk "$DIST"/*_noarch.apk; do
            [ -f "$f" ] || continue
            # Rename nfpm output `<name>_<ver>_<arch>.apk` to the apk-tools
            # standard `<name>-<ver>-r0.apk` (= without F: fields in
            # APKINDEX, apk-tools fetches by the standard name).
            base=$(basename "$f" .apk)
            # name = strip the trailing '_<ver>_<arch>' portion
            name=$(echo "$base" | sed -E 's/_[0-9].*//')
            ver=$(echo "$base" | sed -E "s/^${name}_//; s/_(x86_64|aarch64|noarch)$//")
            # apk-tools uses APKINDEX's V: field as the filename suffix.
            # nfpm output pkgver is "0.1.0" (= no -r0), so the filename
            # also has no `-r0`.
            newname="${name}-${ver}.apk"
            cp "$f" "$d/$newname"
        done
        # skip if no apks to index
        [ "$(ls "$d"/*.apk 2>/dev/null | wc -l)" -gt 0 ] || continue
        # --description: required for apk-tools v3 to recognize APKINDEX
        # (= confirmed via 2026-05-11 [B]).
        ( cd "$d" && apk index --quiet --description "unmask repository (single-path)" -o APKINDEX.tar.gz *.apk )
        if [ -n "${UNMASK_RSA_PRIVKEY:-}" ] && [ -f "$UNMASK_RSA_PRIVKEY" ]; then
            abuild-sign -k "$UNMASK_RSA_PRIVKEY" "$d/APKINDEX.tar.gz"
        fi
    done
else
    echo "==> apk stage: skip (= apk absent / keeping existing $OUT/apk)"
fi

# ---- summary ----
echo
echo "==> repo built at: $OUT"
du -sh "$OUT"/* 2>/dev/null || true
echo
echo "next: run tools/publish-repo.sh to rsync to unmask.sh:/var/www/unmask.sh/dl/."
