#!/bin/bash
# tools/build-repo.sh — take the rpm/deb/apk files under dist/ and assemble
# the repo layout to be published at unmask.sh:/var/www/unmask.sh/dl/ under
# repo/.
#
# usage:
#   ./tools/build-repo.sh [OUT_DIR] [STAGE]
#
#   OUT_DIR default: ../unmask-dl-build (= sibling of the working tree so the
#   build output stays out of the git index).  Production publish is handled
#   by a separate script (= tools/publish-repo.sh) that rsyncs to
#   unmask.sh:/var/www/unmask.sh/dl/.
#
#   STAGE default: all (= run rpm + deb + apk stages back to back).
#   Pass `apk` (or `rpm` / `deb`) to run only that stage and leave the other
#   stages' output untouched.  Used by `make repo-apk` to run the apk stage
#   inside an Alpine container (apk-tools / abuild are not present on Rocky).
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
#   UNMASK_GPG_KEY_ID=C03DD45E28C4446FDDC48EFC34A320B544B28158  # rpm/deb signing key (fpr)
#   UNMASK_GNUPGHOME=../keys/gpg                                # project-local keyring (default: a keys/gpg dir beside the repo checkout)
#   UNMASK_GPG_PASSPHRASE=...                                   # for batch / CI runs.  Omit to be prompted via read -s
#   UNMASK_RSA_PRIVKEY=~/.abuild/...rsa                         # signing key for apk index
# If UNMASK_GPG_KEY_ID is unset, signing is skipped (= dry run).
#
# Why preset the passphrase up front (= rather than letting each rpm --addsign /
# gpg --detach-sign prompt):
#   - rpm 4.16 + GnuPG 2.3 in Rocky 9 cannot prompt non-interactively when the
#     surrounding context has no controlling TTY (= sudo -iu apps shell, nohup,
#     cron).  pinentry-tty / pinentry-curses fail with 'inappropriate ioctl'.
#   - We cache the passphrase once via PRESET_PASSPHRASE into the agent and let
#     every subsequent sign hit the cache.  The cache TTL is bounded by the
#     agent's max-cache-ttl (= the gpg-agent.conf inside that GNUPGHOME).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
OUT="${1:-$ROOT/../unmask-dl-build}"
STAGE="${2:-all}"

case "$STAGE" in
    all|rpm|deb|apk) ;;
    *) echo "ERR: unknown stage '$STAGE'.  Valid: all | rpm | deb | apk." >&2; exit 1 ;;
esac

# DIST is only required for stages that read from it.  The apk-only path,
# when invoked inside the Alpine container, also expects DIST to be present
# because the indexer copies the *.apk files into the per-arch directory
# before running `apk index`.
[ -d "$DIST" ] || { echo "ERR: $DIST not found.  Run 'make package' first." >&2; exit 1; }

# Helper: is the requested stage active?
stage_active() {
    [ "$STAGE" = "all" ] || [ "$STAGE" = "$1" ]
}

# ---- GnuPG keyring + agent passphrase preset ----
# Project-local GNUPGHOME (= the unmask release keyring lives outside ~/.gnupg
# so user keyrings stay unaffected and CI runs are deterministic).
export GNUPGHOME="${UNMASK_GNUPGHOME:-$(dirname "$ROOT")/keys/gpg}"
[ -d "$GNUPGHOME" ] || {
    echo "WARN: GNUPGHOME=$GNUPGHOME absent.  Continuing -- signing will be skipped if UNMASK_GPG_KEY_ID is set."
}

# Preset the passphrase into the agent cache exactly once per build-repo invocation.
# Idempotent: a second call within the same shell skips when UNMASK_GPG_PRESET_DONE is set.
# Skip entirely when only the apk stage is requested -- apk signing uses
# abuild-sign / RSA, not GPG.
if [ -n "${UNMASK_GPG_KEY_ID:-}" ] && [ -z "${UNMASK_GPG_PRESET_DONE:-}" ] \
        && { stage_active rpm || stage_active deb; }; then
    KEYGRIP=$(gpg --list-keys --with-keygrip --with-colons "$UNMASK_GPG_KEY_ID" 2>/dev/null \
        | awk -F: '$1=="grp"{print $10; exit}')
    if [ -z "$KEYGRIP" ]; then
        echo "ERR: cannot find keygrip for $UNMASK_GPG_KEY_ID under GNUPGHOME=$GNUPGHOME" >&2
        echo "     -> gpg --list-secret-keys to verify the key is imported." >&2
        exit 1
    fi
    if [ -z "${UNMASK_GPG_PASSPHRASE:-}" ]; then
        printf "GPG passphrase for %s: " "$UNMASK_GPG_KEY_ID" >&2
        stty -echo 2>/dev/null
        IFS= read -r UNMASK_GPG_PASSPHRASE
        stty echo 2>/dev/null
        printf '\n' >&2
        export UNMASK_GPG_PASSPHRASE
    fi
    # PRESET_PASSPHRASE wants hex-encoded passphrase.  od + tr is portable.
    HEX=$(printf '%s' "$UNMASK_GPG_PASSPHRASE" | od -An -tx1 | tr -d ' \n')
    gpg-connect-agent <<EOF >/dev/null 2>&1
PRESET_PASSPHRASE $KEYGRIP -1 $HEX
EOF
    UNMASK_GPG_PRESET_DONE=1
    export UNMASK_GPG_PRESET_DONE
    # Verify the cache landed by signing a probe through gpg-agent.  The
    # passphrase is already preset into the agent above, so the probe doesn't
    # need to pass --passphrase on argv (which would expose the secret to any
    # local user running `ps -ef` during the few ms gpg is alive).
    if ! echo probe | gpg --batch \
            --local-user "$UNMASK_GPG_KEY_ID" --clearsign >/dev/null 2>&1; then
        echo "ERR: GPG signing probe failed.  Wrong passphrase, or key not in $GNUPGHOME ?" >&2
        exit 1
    fi
    echo "==> gpg passphrase preset for $UNMASK_GPG_KEY_ID (keygrip ${KEYGRIP:0:16}...)"
fi

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

echo "==> output: $OUT  (stage=$STAGE)"
mkdir -p "$OUT"/{rpm,deb,apk,keys}

# ---- /dl/ landing page (= the custom index served at unmask.sh/dl/) ----
# Evergreen (links to dirs + /install/, no per-build data), so always refresh.
# Must live in $OUT: publish-repo.sh rsyncs with --delete-after, which would
# nuke a hand-placed dl/index.html that is not part of the build output.
if [ -f "$ROOT/tools/dl-index.html" ]; then
    cp "$ROOT/tools/dl-index.html" "$OUT/index.html"
    echo "  -> dl/index.html (custom repo landing)"
fi
# The Japanese landing lives at the site path /ja/dl/ (not under /dl/), so it is
# NOT placed in the repo tree here -- it ships with the site (deployed to
# /var/www/unmask.sh/ja/dl/index.html from tools/dl-index.ja.html).
# Theme assets for the autoindex sub-directory listings (rpm/, deb/, ...).
# Served from /dl/ (auth-free pre-GA, unlike /static) and injected into the
# stock autoindex HTML via sub_filter; must live in $OUT to survive
# publish-repo.sh's --delete-after.
for asset in dlindex.css dlindex.js; do
    if [ -f "$ROOT/tools/$asset" ]; then
        cp "$ROOT/tools/$asset" "$OUT/$asset"
        echo "  -> dl/$asset (autoindex theme)"
    fi
done

# ---- keys (= always overwrite with the latest public key. idempotent because the files are small) ----
# Only refresh keys/ on a full run.  apk-only invocations (= the Alpine
# container path) deliberately leave keys/ alone -- the existing files may be
# owned by root from a previous full run and would otherwise fail with EACCES
# under the container's non-root uid.  Keys are regenerated whenever the rpm
# / deb stages run (= the host-side `make repo` flow).
if stage_active rpm || stage_active deb; then
    cp "$ROOT/rpm/release/RPM-GPG-KEY-unmask" "$OUT/keys/RPM-GPG-KEY-unmask"
    cp "$ROOT/rpm/release/unmask.rsa.pub"      "$OUT/keys/unmask.rsa.pub"
    # apk signing pub key, so the Alpine bootstrap can drop it into
    # /etc/apk/keys/.  Guarded: place the .pub at rpm/release/ to publish it
    # (the matching private signer key lives in the offline key store).
    [ -f "$ROOT/rpm/release/oss@unmask.sh-260509.rsa.pub" ] &&
        cp "$ROOT/rpm/release/oss@unmask.sh-260509.rsa.pub" "$OUT/keys/oss@unmask.sh-260509.rsa.pub"
fi

# ============================================================
# rpm stage (= regenerate if createrepo_c is present; otherwise leave the existing tree)
# ============================================================
if ! stage_active rpm; then
    echo "==> rpm stage: skip (= stage filter '$STAGE')"
elif [ "$HAVE_CREATEREPO" = 1 ]; then
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
        # latest alias for unmask-release (= install docs link to a stable URL)
        latest=$(ls -1 "$arch_dir"/unmask-release-[0-9]*.noarch.rpm 2>/dev/null | sort -V | tail -1)
        [ -n "$latest" ] && cp -f "$latest" "$arch_dir/unmask-release-latest.noarch.rpm"
    done
    # Also drop the noarch release alias at the TOP of /dl/rpm/ -- the install
    # docs link to the stable, arch-independent
    # https://unmask.sh/dl/rpm/unmask-release-latest.noarch.rpm, and
    # `dnf install <url>` fetches it directly (no repodata lookup).
    rel=$(ls -1 "$DIST"/unmask-release-[0-9]*.noarch.rpm 2>/dev/null | sort -V | tail -1)
    [ -n "$rel" ] && cp -f "$rel" "$OUT/rpm/unmask-release-latest.noarch.rpm"

    # sign packages + generate repodata
    for arch in x86_64 aarch64; do
        arch_dir="$OUT/rpm/$arch"
        [ -d "$arch_dir/RPMS" ] || continue
        # GPG-sign each rpm package (= required for dnf gpgcheck=1).  Done
        # before createrepo_c so the metadata hashes the signed files.
        # Idempotent: re-signing an already-signed rpm replaces the signature.
        # The signing key must be RSA -- rpm 4.16 (EL9) cannot create or
        # verify ed25519/EdDSA signatures.
        if [ -n "${UNMASK_GPG_KEY_ID:-}" ]; then
            echo "  -> sign rpms in $arch_dir/RPMS (key=$UNMASK_GPG_KEY_ID)"
            for r in "$arch_dir"/RPMS/*.rpm; do
                [ -f "$r" ] || continue
                rpm --addsign --define "_gpg_name $UNMASK_GPG_KEY_ID" "$r" >/dev/null
            done
        else
            echo "  -> WARNING: UNMASK_GPG_KEY_ID unset -> rpms NOT signed (dnf gpgcheck=1 will fail)"
        fi
        echo "  -> createrepo_c $arch_dir"
        createrepo_c --quiet "$arch_dir"
        # sign the repo metadata (= repo_gpgcheck=1)
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
if ! stage_active deb; then
    echo "==> deb stage: skip (= stage filter '$STAGE')"
elif [ "$HAVE_APT" = 1 ]; then
    echo "==> deb stage: regenerate (= single path / Suites: stable)"
    rm -rf "$OUT/deb"
    mkdir -p "$OUT/deb"

    POOL="$OUT/deb/pool/main/u/unmask"
    mkdir -p "$POOL"
    cp "$DIST"/*.deb "$POOL"/ 2>/dev/null || true
    # latest alias for unmask-release (= install docs link to a stable URL)
    latest=$(ls -1 "$POOL"/unmask-release_[0-9]*_all.deb 2>/dev/null | sort -V | tail -1)
    [ -n "$latest" ] && cp -f "$latest" "$POOL/unmask-release_latest_all.deb"
    # Also drop it at the TOP of /dl/deb/ with the filename the install docs use
    # (https://unmask.sh/dl/deb/unmask-release-latest.deb); `apt install <url>`
    # fetches it directly.
    [ -n "$latest" ] && cp -f "$latest" "$OUT/deb/unmask-release-latest.deb"

    DSTABLE="$OUT/deb/dists/stable"
    for arch in amd64 arm64; do
        bin="$DSTABLE/main/binary-$arch"
        mkdir -p "$bin"
        ( cd "$OUT/deb" && apt-ftparchive --arch "$arch" packages "pool/main" ) > "$bin/Packages"
        gzip -kf "$bin/Packages"
    done

    # Release = headers + per-file hash sections.  apt-ftparchive's `release`
    # subcommand scans $DSTABLE and appends the MD5Sum/SHA256 sections; without
    # them apt fails with "Unable to find expected entry main/binary-*/Packages
    # in Release file".  Write via a temp file outside $DSTABLE so the Release
    # is not hashed into its own listing.
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=unmask \
        -o APT::FTPArchive::Release::Label=unmask \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        -o APT::FTPArchive::Release::Description="unmask package repository (single-path / distro-neutral)" \
        release "$DSTABLE" > "$OUT/deb/.Release.tmp"
    mv "$OUT/deb/.Release.tmp" "$DSTABLE/Release"
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
if ! stage_active apk; then
    echo "==> apk stage: skip (= stage filter '$STAGE')"
elif [ "$HAVE_APK" = 1 ]; then
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
        # latest alias for unmask-release (= install docs link to a stable URL,
        # parallel to rpm's unmask-release-latest.noarch.rpm and deb's
        # unmask-release_latest_all.deb).  apk add reads metadata from the
        # file content, so the alias filename is purely a download URL anchor.
        latest=$(ls -1 "$d"/unmask-release-[0-9]*.apk 2>/dev/null | sort -V | tail -1)
        [ -n "$latest" ] && cp -f "$latest" "$d/unmask-release-latest.apk"
        # --description: required for apk-tools v3 to recognize APKINDEX
        # (= confirmed via 2026-05-11 [B]).
        # --allow-untrusted: `apk index` validates each input .apk against the
        # local /etc/apk/keys/ keyring.  In the Alpine container our public
        # key is not installed at /etc/apk/keys/ (= the container runs as a
        # non-root uid and we ship the pub key separately via unmask-release).
        # The signature on APKINDEX.tar.gz produced by `abuild-sign` below is
        # what clients verify; the index-time check is developer-side only.
        ( cd "$d" && apk index --quiet --allow-untrusted --description "unmask repository (single-path)" -o APKINDEX.tar.gz *.apk )
        if [ -n "${UNMASK_RSA_PRIVKEY:-}" ] && [ -f "$UNMASK_RSA_PRIVKEY" ]; then
            # -p sets the pub-key NAME embedded in the index signature filename
            # (= `.SIGN.RSA.<pubname>` inside APKINDEX.tar.gz).  apk-tools looks
            # up `/etc/apk/keys/<pubname>` on the client.  Without -p,
            # abuild-sign tries to read `${UNMASK_RSA_PRIVKEY}.pub` from disk
            # which we do not ship -- the public key is distributed separately
            # via the unmask-release package (= /etc/apk/keys/oss@unmask.sh-260509.rsa.pub).
            pubname="${UNMASK_RSA_PUBNAME:-$(basename "$UNMASK_RSA_PRIVKEY").pub}"
            abuild-sign -k "$UNMASK_RSA_PRIVKEY" -p "$pubname" "$d/APKINDEX.tar.gz"
        else
            echo "  -> WARNING: UNMASK_RSA_PRIVKEY unset or missing -> APKINDEX NOT signed (apk add will reject the repo)"
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
