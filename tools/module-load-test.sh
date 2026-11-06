#!/bin/sh
# Load a built ngx_http_unmask_module.so into the nginx of a distribution it
# is built for, and ask that nginx whether it will start with it.
#
# The three older ABIs are built in containers (build-docker/) and until now
# were only ever loaded on the maintainer's lab before a release; nothing in
# this tree or in CI ran them.  That matters most when the build changes: a
# linker option such as BIND_NOW turns a symbol the host cannot resolve into
# a refused load, which is the right failure -- and one that has to be seen
# here, not on a host.  `nginx -t` with a load_module line is the whole test:
# it dlopen()s the module, checks its signature against the binary, and
# parses a directive only the module provides.
#
#   module-load-test.sh <abi> [dist dir]
#     abi       openssl11 | openssl10 | glibc212
#     dist dir  where the multi-modules-* caches are (default: dist)
#
# Needs docker and the network (the container installs its distribution's
# nginx, or nginx.org's package where the distribution has none).
set -eu

ABI="${1:-}"
DIST="${2:-dist}"
case "$ABI" in
openssl11)
	# AlmaLinux 8: OpenSSL 1.1.1, nginx 1.24 from its module stream.
	IMAGE=almalinux:8
	VER=1.24.0
	CACHE=multi-modules-openssl11
	INSTALL='dnf -q -y module enable nginx:1.24 >/dev/null && dnf -q -y install nginx >/dev/null'
	;;
openssl10)
	# CentOS 7: OpenSSL 1.0.2.  Its repositories are gone (EOL), so the
	# nginx.org package for it is fetched and unpacked directly.
	IMAGE=centos:7
	VER=1.20.1
	CACHE=multi-modules-openssl10
	INSTALL='curl -fsS -o /tmp/nginx.rpm http://nginx.org/packages/centos/7/x86_64/RPMS/nginx-1.20.1-1.el7.ngx.x86_64.rpm && rpm -U --nodeps /tmp/nginx.rpm >/dev/null 2>&1'
	;;
glibc212)
	# CentOS 6: glibc 2.12, OpenSSL 1.0.1.  Same as above (and plain http:
	# its OpenSSL cannot reach a current TLS endpoint).
	IMAGE=centos:6
	VER=1.18.0
	CACHE=multi-modules-glibc212
	INSTALL='curl -fsS -o /tmp/nginx.rpm http://nginx.org/packages/centos/6/x86_64/RPMS/nginx-1.18.0-2.el6.ngx.x86_64.rpm && rpm -U --nodeps /tmp/nginx.rpm >/dev/null 2>&1'
	;;
*)
	echo "usage: module-load-test.sh openssl11|openssl10|glibc212 [dist dir]" >&2
	exit 2
	;;
esac

SO="$DIST/$CACHE/$VER/ngx_http_unmask_module.so"
[ -f "$SO" ] || { echo "module-load-test: $SO is not built (make build-module-multi-${ABI})" >&2; exit 2; }
SO_ABS="$(cd "$(dirname "$SO")" && pwd)/$(basename "$SO")"

# The directive is one only the module knows, so a configuration that parses
# proves the module was loaded and registered, not merely that the file
# opened.  The secret is a placeholder: nothing is served.
docker run --rm --platform=linux/amd64 -v "$SO_ABS:/mod/ngx_http_unmask_module.so:ro" "$IMAGE" sh -c "
set -e
$INSTALL
command -v nginx >/dev/null
cat > /tmp/nginx.conf <<'CONF'
load_module /mod/ngx_http_unmask_module.so;
events {}
http {
    unmask_bv_secret \"module-load-test-placeholder-secret\";
    server { listen 127.0.0.1:8080; }
}
CONF
nginx -v 2>&1
nginx -t -c /tmp/nginx.conf
" || { echo "module-load-test: $ABI: nginx $VER on $IMAGE refused the module" >&2; exit 1; }
echo "module-load-test: $ABI: nginx $VER on $IMAGE loads $SO"
