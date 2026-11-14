#!/bin/sh
# tools/check-nginx-releases.sh -- is there an nginx release the plugin package
# should carry a module for, and does not?
#
#   usage: tools/check-nginx-releases.sh
#
# nginx loads a dynamic module only when it was built for nginx's exact
# version, patch release included, so the plugin package names releases
# (PLUGIN_NGINX_VERSIONS in the Makefile).  Two lists move without this repo
# moving with them:
#   - nginx.org adds a release to its stable branch.  The package carries
#     every release of the newest stable branch: an nginx built from source,
#     or by a hosting panel, stays on whichever was the newest the day it was
#     built.
#   - a hosting panel changes the release it builds for a stable branch.
#     aaPanel and BT Panel name it in their nginx install script, one line per
#     branch (nginx_130='1.30.6'), and rebuild a host's nginx to it on update.
# Mainline branches (odd minor) are not bundled, and are not looked at.
#
# Prints each release that is missing with where it comes from, and exits 1;
# exits 0 when nothing is missing, 2 when a source could not be read.  The
# nginx-releases workflow runs it every day.  Adding a release: pin its
# tarball (nginx-module/nginx-sha256sums.txt says how), add it to
# PLUGIN_NGINX_VERSIONS and to the module-matrix workflow.
#
# Environment:
#   PLUGIN_NGINX_VERSIONS  the bundled releases, instead of the Makefile's
#   NGINX_DOWNLOAD_INDEX   default https://nginx.org/download/
#   PANEL_SCRIPTS          default: aaPanel's and BT Panel's nginx.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
have="${PLUGIN_NGINX_VERSIONS:-$(sed -n 's/^PLUGIN_NGINX_VERSIONS ?= //p' "$here/Makefile")}"
[ -n "$have" ] || { echo "PLUGIN_NGINX_VERSIONS not found in $here/Makefile" >&2; exit 2; }
index="${NGINX_DOWNLOAD_INDEX:-https://nginx.org/download/}"
panels="${PANEL_SCRIPTS:-aaPanel=https://node.aapanel.com/install/0/nginx.sh BT-Panel=https://download.bt.cn/install/0/nginx.sh}"

fetch() { curl -fsSL --max-time 30 -A 'unmask-ci nginx-releases' "$1"; }
bundled() { case " $have " in *" $1 "*) return 0 ;; esac; return 1; }

missing=0
report() { # <release> <where it comes from>
    echo "missing: nginx $1 ($2)"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::error::no module for nginx $1 ($2)"
    missing=$((missing + 1))
}

# --- nginx.org: every release of the newest stable branch ---
page=$(fetch "$index") || { echo "cannot read $index" >&2; exit 2; }
releases=$(printf '%s\n' "$page" | sed -n 's/.*href="nginx-\(1\.[0-9]*\.[0-9]*\)\.tar\.gz".*/\1/p' | sort -u -V)
[ -n "$releases" ] || { echo "no nginx release found in $index" >&2; exit 2; }
stable=$(printf '%s\n' "$releases" | awk -F. '$2 % 2 == 0 { print $1 "." $2 }' | sort -u -V | tail -n 1)
echo "nginx.org: the newest stable branch is $stable"
for v in $(printf '%s\n' "$releases" | grep "^$(echo "$stable" | sed 's/\./\\./g')\."); do
    bundled "$v" || report "$v" "nginx.org, a release of the stable branch $stable"
done

# --- the panels: the release each builds for a stable branch ---
for p in $panels; do
    name=${p%%=*}; url=${p#*=}
    script=$(fetch "$url") || { echo "cannot read $url" >&2; exit 2; }
    map=$(printf '%s\n' "$script" | sed -n "s/^[[:space:]]*nginx_1\([0-9]*\)='\(1\.[0-9]*\.[0-9]*\)'.*/\1 \2/p")
    [ -n "$map" ] || { echo "no nginx_1XX='...' line in $url" >&2; exit 2; }
    n=0
    for v in $(printf '%s\n' "$map" | awk '$1 % 2 == 0 && $1 >= 10 { print $2 }'); do
        n=$((n + 1))
        bundled "$v" || report "$v" "$name builds it for ${v%.*}"
    done
    echo "$name: $n stable branches"
done

if [ "$missing" -gt 0 ]; then
    echo "$missing release(s) without a module in the plugin package"
    exit 1
fi
echo "every release looked at has a module in the plugin package"
