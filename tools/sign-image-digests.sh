#!/bin/sh
# tools/sign-image-digests.sh -- sign the list of image digests a release
# publishes.
#
#   usage: tools/sign-image-digests.sh <version>
#
# tools/build-registry.sh writes docker/digests-<version>.txt into the
# dl-build tree: one "sha256:<hex>  unmask:<tag>" line for every tag the
# static registry holds.  This signs that list with the release key -- the
# one that signs the packages and checksums.txt -- as
# digests-<version>.txt.asc, and the moving copy (digests.txt) the same way.
#
# The registry is static files on the download host, and a tag there is
# whatever file the host serves for it.  The signature is made on the build
# host, so whoever holds the download host can replace an image and the list
# but not sign for it, and a downloader needs gpg alone to know which image
# a version is:
#
#   curl -fsSL --remote-name-all https://unmask.sh/dl/docker/digests-<version>.txt{,.asc}
#   gpg --verify digests-<version>.txt.asc digests-<version>.txt
#   docker pull unmask.sh/unmask@sha256:<the digest on the version's line>
#
# A pull by digest is checked by the client against that digest, whichever
# host answers it.
#
# Environment:
#   UNMASK_GPG_KEY_ID     required: the release key (fingerprint)
#   UNMASK_GNUPGHOME      default: a keys/gpg directory beside the checkout
#   UNMASK_DL_BUILD_DIR   default ../unmask-dl-build
#
# The passphrase is the agent's to have (tools/with-gpg-preset.sh, or the
# signing earlier in the same run): this asks for nothing and fails when the
# agent does not hold it.
set -eu

VER="${1:?usage: sign-image-digests.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${UNMASK_DL_BUILD_DIR:-$ROOT/../unmask-dl-build}"
export GNUPGHOME="${UNMASK_GNUPGHOME:-$(dirname "$ROOT")/keys/gpg}"
: "${UNMASK_GPG_KEY_ID:?UNMASK_GPG_KEY_ID is not set}"

die() { echo "sign-image-digests: $*" >&2; exit 1; }

list="$OUT/docker/digests-$VER.txt"
[ -s "$list" ] || die "$list is missing or empty (tools/build-registry.sh $VER writes it)"
cmp -s "$list" "$OUT/docker/digests.txt" || die "$OUT/docker/digests.txt is not a copy of digests-$VER.txt"

# The list says what the tree serves: the version's line names the manifest
# laid out for the version.
want="$(awk -v t="unmask:$VER" '$2 == t { print $1 }' "$list")"
[ -n "$want" ] || die "$list has no line for unmask:$VER"
man="$OUT/registry/v2/unmask/manifests/$VER.idx"
[ -f "$man" ] || man="$OUT/registry/v2/unmask/manifests/$VER.man"
[ -f "$man" ] || die "the registry tree has no manifest for unmask:$VER"
got="sha256:$(sha256sum "$man" | cut -d' ' -f1)"
[ "$got" = "$want" ] || die "the list names $want for unmask:$VER, the registry tree serves $got"

gpg --batch --yes --pinentry-mode error --local-user "$UNMASK_GPG_KEY_ID" \
    --armor --detach-sign -o "$list.asc" "$list" \
    || die "gpg did not sign $list (is the passphrase in the agent?)"
LC_ALL=C gpg --batch --verify "$list.asc" "$list" 2>&1 | grep -q 'Good signature' \
    || die "the signature just made on $list does not verify"
cp "$list.asc" "$OUT/docker/digests.txt.asc"
echo "==> signed: $list.asc ($want  unmask:$VER)"
