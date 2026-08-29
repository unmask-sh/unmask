#!/bin/bash
# tools/build-registry.sh -- assemble the container-image half of a release
# for unmask.sh: the static registry tree that /v2/ serves, and the compose
# file under /dl/docker/.  Run after the release workflow has pushed the
# images to GHCR (the CI build host does the multi-arch build; unmask.sh is
# where people pull from).
#
# usage:
#   tools/build-registry.sh <version>            e.g. 0.1.37
#
# Environment:
#   UNMASK_DL_BUILD_DIR   default ../unmask-dl-build (publish-repo.sh reads it)
#   UNMASK_IMAGE_SOURCE   default ghcr.io/unmask-sh  (where the release pushed)
#   UNMASK_NGINX_VERSION  default 1.28.3             (the nginx image's tag suffix)
#   SKOPEO                default: skopeo if installed, else quay.io/skopeo/stable in docker
#
# Then: tools/publish-repo.sh (rsyncs registry/ -> /v2/ and docker/ -> /dl/docker/).
set -eu
VER="${1:?usage: build-registry.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${UNMASK_DL_BUILD_DIR:-$ROOT/../unmask-dl-build}"
SRC="${UNMASK_IMAGE_SOURCE:-ghcr.io/unmask-sh}"
NGX="${UNMASK_NGINX_VERSION:-1.28.3}"
NGX_MINOR="${NGX%.*}"
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

lay() {   # <name> <source tag> <tag>...
    local name="$1" src="$2"; shift 2
    local dir="$WORK/$name"; mkdir -p "$dir"
    echo "==> $SRC/$name:$src -> OCI layout"
    skopeo_copy "$SRC/$name:$src" "$dir" "$src"
    local args=(); for t in "$@"; do args+=(--tag "$t"); done
    python3 "$ROOT/tools/oci-static-registry.py" --layout "$dir" --ref "$src" \
        --name "$name" "${args[@]}" --out "$OUT/registry"
}

mkdir -p "$OUT/registry" "$OUT/docker"
lay admin "$VER"       "$VER" latest
lay nginx "$VER-$NGX"  "$VER-$NGX" "$NGX" "$NGX_MINOR" latest

# The compose file people fetch, pinned per version and as the moving copy.
cp "$ROOT/docker-compose.example.yml" "$OUT/docker/docker-compose-$VER.yml"
cp "$ROOT/docker-compose.example.yml" "$OUT/docker/docker-compose.yml"

# Digests, for anyone who pins images (docker pull unmask.sh/admin@sha256:...).
{
    for name in admin nginx; do
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
