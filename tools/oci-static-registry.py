#!/usr/bin/env python3
"""tools/oci-static-registry.py -- lay an OCI image layout out as files that
plain nginx serves as a registry (docker/registry/oci-static.inc).

unmask.sh is the primary distribution point for the container images, the
same way it is for the rpm/deb/apk repositories.  Nothing runs there but
nginx, so the registry is a directory: manifests and blobs are files, and
the include gives them the media types and headers the Distribution API
promises.  A pull is then GET /v2/<name>/manifests/<tag> (the multi-arch
index), GET /v2/<name>/manifests/sha256:... (the platform manifest), and
GET /v2/<name>/blobs/sha256:... for config and layers -- all static.

Input is an OCI image layout (oci-layout + index.json + blobs/sha256/*), as
written by `skopeo copy --all --format oci docker://... oci:DIR` or by
`docker buildx build --output type=oci,dest=x.tar` (untarred).

Output tree, under OUT/v2/NAME/:
  manifests/<tag>.idx            the image index (multi-arch) for each tag
  manifests/sha256:<hex>.idx     the same index, addressed by digest
  manifests/sha256:<hex>.man     every platform / attestation manifest
  blobs/sha256:<hex>             configs and layers
  tags/list                      {"name": NAME, "tags": [...]} (merged)

A single-platform layout (index.json pointing straight at a manifest) is
laid out the same way with .man for the tag.  nginx tries .idx first and
falls back to .man, each with its own Content-Type.

Usage:
  oci-static-registry.py --layout DIR --name admin --tag 0.1.37 --tag latest --out ../unmask-dl-build/registry
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def blob_path(layout, digest):
    algo, hexd = digest.split(":", 1)
    return os.path.join(layout, "blobs", algo, hexd)


def read_blob(layout, digest):
    with open(blob_path(layout, digest), "rb") as f:
        data = f.read()
    algo, hexd = digest.split(":", 1)
    if algo != "sha256" or hashlib.sha256(data).hexdigest() != hexd:
        sys.exit(f"blob {digest}: content does not match its digest")
    return data


def write_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def copy_blob(layout, digest, out_blobs):
    dst = os.path.join(out_blobs, digest)
    if os.path.exists(dst):
        return 0
    src = blob_path(layout, digest)
    os.makedirs(out_blobs, exist_ok=True)
    tmp = dst + ".tmp"
    try:
        os.link(src, tmp)
    except OSError:
        shutil.copyfile(src, tmp)
    os.replace(tmp, dst)
    return os.path.getsize(dst)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layout", required=True, help="OCI image layout directory")
    ap.add_argument("--name", required=True, help="repository name under /v2/ (e.g. admin)")
    ap.add_argument("--tag", action="append", default=[], help="tag to point at the image (repeatable)")
    ap.add_argument("--ref", help="index.json entry to use, by org.opencontainers.image.ref.name annotation (when the layout holds several)")
    ap.add_argument("--out", required=True, help="registry tree root; files go under OUT/v2/NAME/")
    a = ap.parse_args()
    if not a.tag:
        sys.exit("at least one --tag is required")

    with open(os.path.join(a.layout, "index.json"), "rb") as f:
        index = json.load(f)
    entries = index.get("manifests", [])
    if a.ref:
        entries = [e for e in entries if e.get("annotations", {}).get("org.opencontainers.image.ref.name") == a.ref]
    if len(entries) != 1:
        sys.exit(f"index.json holds {len(entries)} matching entries; pass --ref to pick one")
    top = entries[0]
    top_digest = top["digest"]
    top_bytes = read_blob(a.layout, top_digest)
    top_doc = json.loads(top_bytes)
    top_type = top.get("mediaType") or top_doc.get("mediaType", "")

    repo = os.path.join(a.out, "v2", a.name)
    out_manifests = os.path.join(repo, "manifests")
    out_blobs = os.path.join(repo, "blobs")
    copied = 0
    platforms = []

    def lay_manifest(digest, data, doc):
        nonlocal copied
        write_atomic(os.path.join(out_manifests, digest + ".man"), data)
        copied += copy_blob(a.layout, doc["config"]["digest"], out_blobs)
        for layer in doc.get("layers", []):
            copied += copy_blob(a.layout, layer["digest"], out_blobs)

    if top_type in INDEX_TYPES:
        kind = "idx"
        write_atomic(os.path.join(out_manifests, top_digest + ".idx"), top_bytes)
        for child in top_doc.get("manifests", []):
            cdata = read_blob(a.layout, child["digest"])
            cdoc = json.loads(cdata)
            ctype = child.get("mediaType") or cdoc.get("mediaType", "")
            if ctype in INDEX_TYPES:
                sys.exit(f"nested index {child['digest']} is not supported")
            lay_manifest(child["digest"], cdata, cdoc)
            p = child.get("platform") or {}
            platforms.append(f"{p.get('os', '?')}/{p.get('architecture', '?')}")
    elif top_type in MANIFEST_TYPES:
        kind = "man"
        lay_manifest(top_digest, top_bytes, top_doc)
        platforms.append("single")
    else:
        sys.exit(f"unsupported top-level media type {top_type!r}")

    for tag in a.tag:
        write_atomic(os.path.join(out_manifests, f"{tag}.{kind}"), top_bytes)
        # A tag that changes kind (index today, manifest yesterday) must not
        # leave the other file behind: nginx tries .idx first.
        other = os.path.join(out_manifests, f"{tag}.{'man' if kind == 'idx' else 'idx'}")
        if os.path.exists(other):
            os.remove(other)

    tags_path = os.path.join(repo, "tags", "list")
    tags = []
    if os.path.exists(tags_path):
        with open(tags_path, "rb") as f:
            tags = json.load(f).get("tags", [])
    for tag in a.tag:
        if tag not in tags:
            tags.append(tag)
    write_atomic(tags_path, json.dumps({"name": a.name, "tags": sorted(tags)}, separators=(",", ":")).encode() + b"\n")

    print(f"{a.name}: {', '.join(a.tag)} -> {top_digest} ({', '.join(platforms)}; {copied / 1e6:.1f} MB of new blobs)")


if __name__ == "__main__":
    main()
