# unmask.sh static container registry -- server scope, next to /dl/.
#
# The tree under $document_root/v2/ is written by tools/oci-static-registry.py
# (manifests as <ref>.idx / <ref>.man, blobs by digest) and published with
# tools/publish-repo.sh.  These locations give the files the media types and
# headers of the Distribution API, so `docker pull unmask.sh/admin` is a
# handful of static GETs.  Like /dl/, none of this goes through the
# challenge: a container runtime is not a browser.  Needs
# oci-static-map.conf in the http scope (loaded after the unmask include).

location = /v2/ {
    auth_basic off;
    add_header Docker-Distribution-API-Version "registry/2.0" always;
    default_type application/json;
    return 200 '{}';
}

location ~ "^/v2/(?<oci_name>[a-z0-9._-]+)/manifests/(?<oci_ref>[A-Za-z0-9._:-]+)$" {
    auth_basic off;
    add_header Docker-Distribution-API-Version "registry/2.0" always;
    add_header Docker-Content-Digest $oci_ref_digest always;
    default_type application/vnd.oci.image.index.v1+json;
    try_files /v2/$oci_name/manifests/$oci_ref.idx @oci_manifest;
}

location @oci_manifest {
    add_header Docker-Distribution-API-Version "registry/2.0" always;
    add_header Docker-Content-Digest $oci_ref_digest always;
    default_type application/vnd.oci.image.manifest.v1+json;
    try_files /v2/$oci_name/manifests/$oci_ref.man =404;
}

location ~ "^/v2/(?<oci_blob_name>[a-z0-9._-]+)/blobs/(?<oci_digest>sha256:[0-9a-f]{64})$" {
    auth_basic off;
    add_header Docker-Distribution-API-Version "registry/2.0" always;
    add_header Docker-Content-Digest $oci_digest always;
    add_header Cache-Control "public, max-age=31536000, immutable";
    default_type application/octet-stream;
    try_files /v2/$oci_blob_name/blobs/$oci_digest =404;
}

location ~ "^/v2/(?<oci_tags_name>[a-z0-9._-]+)/tags/list$" {
    auth_basic off;
    add_header Docker-Distribution-API-Version "registry/2.0" always;
    default_type application/json;
    try_files /v2/$oci_tags_name/tags/list =404;
}
