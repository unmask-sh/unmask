#!/bin/bash
# tools/build-registry.sh -- assemble the container-image half of a release
# for unmask.sh: the static registry tree that /v2/ serves, and the compose
# file under /dl/docker/.  Run after the release workflow has pushed the
# images to GHCR (the CI build host does the multi-arch build; unmask.sh is
# where people pull from).
#
# usage:
#   tools/build-registry.sh <version>            e.g. 0.1.37
#   tools/build-registry.sh <version> --from-layouts <dir>
#       use an OCI layout already on disk (<dir>/unmask, with
#       index.json + blobs/, as `docker buildx build --output type=oci`
#       writes after untarring) instead of pulling from GHCR -- for a build
#       host that cannot reach the registry, or images built locally.
#
# The image taken from the registry is the one the release workflow built,
# and nothing else: its build-provenance attestation is verified first (gh
# attestation verify, against release.yml of UNMASK_IMAGE_REPO), the copy is
# made by the digest that attestation names, and the manifest laid out for
# the version has to hash to it.  So what unmask.sh serves under a version is
# what the attestation vouches for, and a downloader can check it under
# either name:
#
#   gh attestation verify oci://unmask.sh/unmask:<version> --repo unmask-sh/unmask
#
# docker/digests-<version>.txt lists the digest of every tag in the tree.
# The release signs that list with the release key (digests-<version>.txt.asc,
# tools/sign-image-digests.sh), for a check that needs gpg alone.
#
# Environment:
#   UNMASK_DL_BUILD_DIR   default ../unmask-dl-build (the publish step reads it)
#   UNMASK_IMAGE_SOURCE   default ghcr.io/unmask-sh  (where the release pushed)
#   UNMASK_IMAGE_REPO     default unmask-sh/unmask   (whose release.yml attested the image)
#   SKOPEO                default: skopeo if installed, else quay.io/skopeo/stable in docker
#
# Then publish: registry/ goes to /v2/ and docker/ to /dl/docker/ on the download host.
set -eu
VER="${1:?usage: build-registry.sh <version> [--from-layouts <dir>]}"
LAYOUTS=""
if [ "${2:-}" = "--from-layouts" ]; then LAYOUTS="${3:?--from-layouts needs a directory}"; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${UNMASK_DL_BUILD_DIR:-$ROOT/../unmask-dl-build}"
SRC="${UNMASK_IMAGE_SOURCE:-ghcr.io/unmask-sh}"
REPO_SLUG="${UNMASK_IMAGE_REPO:-unmask-sh/unmask}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/unmask-registry.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

skopeo_copy() {   # <src ref> <layout dir> <ref name>
    if [ -n "${SKOPEO:-}" ]; then
        "$SKOPEO" copy --all --format oci "docker://$1" "oci:$2:$3"
    elif command -v skopeo >/dev/null 2>&1; then
        skopeo copy --all --format oci "docker://$1" "oci:$2:$3"
    else
        docker run --rm -v "$2:/work" quay.io/skopeo/stable:latest \
            copy --all --format oci "docker://$1" "oci:/work:$3"
        # the container writes as root; the tree must stay ours for publish
        if [ "$(stat -c %u "$2")" != "$(id -u)" ]; then
            sudo -n chown -R "$(id -u):$(id -g)" "$2" 2>/dev/null || true
        fi
    fi
}

# attested_digest <image ref>: the sha256 (hex) of the manifest the registry
# serves for the ref, once its build-provenance attestation from REPO_SLUG's
# release.yml has verified.  Fails, with nothing on stdout, when there is no
# such attestation -- an image pushed by anyone or anything else.
attested_digest() {
    command -v gh >/dev/null 2>&1 || {
        echo "build-registry: gh is needed to verify the image's attestation (an image built here goes in with --from-layouts)" >&2
        return 1
    }
    gh attestation verify "oci://$1" --repo "$REPO_SLUG" \
        --signer-workflow "$REPO_SLUG/.github/workflows/release.yml" --format json \
        > "$WORK/attestation.json" || {
        echo "build-registry: $1 carries no build-provenance attestation from $REPO_SLUG's release.yml" >&2
        return 1
    }
    python3 -I - "$WORK/attestation.json" <<'PY'
import json, sys
found = set()
for a in json.load(open(sys.argv[1], encoding="utf-8")):
    for s in a.get("verificationResult", {}).get("statement", {}).get("subject", []):
        d = s.get("digest", {}).get("sha256", "")
        if d:
            found.add(d)
if len(found) != 1:
    sys.exit("build-registry: the attestation names %d digests, want exactly one" % len(found))
d = found.pop()
if len(d) != 64 or any(c not in "0123456789abcdef" for c in d):
    sys.exit("build-registry: the attestation's digest is not a sha256")
print(d)
PY
}

lay() {   # <name> <source tag> <tag>...
    local name="$1" src="$2"; shift 2
    local args=(); for t in "$@"; do args+=(--tag "$t"); done
    if [ -n "$LAYOUTS" ]; then
        echo "==> $LAYOUTS/$name (OCI layout on disk)"
        python3 "$ROOT/tools/oci-static-registry.py" --layout "$LAYOUTS/$name" \
            --name "$name" "${args[@]}" --out "$OUT/registry"
        return
    fi
    local dir="$WORK/$name" digest got f; mkdir -p "$dir"
    digest="$(attested_digest "$SRC/$name:$src")"
    echo "==> attested: $name:$src sha256:$digest (built by $REPO_SLUG's release.yml)"
    echo "==> $SRC/$name@sha256:$digest -> OCI layout"
    skopeo_copy "$SRC/$name@sha256:$digest" "$dir" "$src"
    python3 "$ROOT/tools/oci-static-registry.py" --layout "$dir" --ref "$src" \
        --name "$name" "${args[@]}" --out "$OUT/registry"
    # What was laid out for the version is the manifest that was attested: a
    # copy that rewrote it (another manifest format) would serve a digest no
    # attestation covers.
    f="$OUT/registry/v2/$name/manifests/$src.idx"
    [ -f "$f" ] || f="$OUT/registry/v2/$name/manifests/$src.man"
    got="$(sha256sum "$f" | cut -d' ' -f1)"
    if [ "$got" != "$digest" ]; then
        echo "build-registry: $name:$src was laid out as sha256:$got, the attested image is sha256:$digest" >&2
        exit 1
    fi
}

mkdir -p "$OUT/registry" "$OUT/docker"
lay unmask "$VER"       "$VER" latest

# The compose file people fetch, pinned per version and as the moving copy.
cp "$ROOT/docker-compose.example.yml" "$OUT/docker/docker-compose-$VER.yml"
cp "$ROOT/docker-compose.example.yml" "$OUT/docker/docker-compose.yml"

# Digests, for anyone who pins images (docker pull unmask.sh/unmask@sha256:...).
{
    for name in unmask; do
        for f in "$OUT/registry/v2/$name/manifests/"*.idx "$OUT/registry/v2/$name/manifests/"*.man; do
            [ -f "$f" ] || continue
            ref="$(basename "$f")"; ref="${ref%.*}"
            case "$ref" in sha256:*) continue ;; esac
            printf 'sha256:%s  %s:%s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$name" "$ref"
        done
    done
} > "$OUT/docker/digests-$VER.txt"
cp "$OUT/docker/digests-$VER.txt" "$OUT/docker/digests.txt"
echo "==> registry tree: $OUT/registry/v2  compose: $OUT/docker"
cat "$OUT/docker/digests-$VER.txt"
