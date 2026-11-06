#!/bin/sh
# Print a short hash of what a module .so is built from: the source
# (nginx-module/config and the non-test .c / .h files), the compiler and
# linker options (nginx-module/hardening.sh) and the container recipes
# (build-docker/*/build-one.sh).  The Makefile stamps every cached module .so
# with it (dist/multi-modules*/<nginx version>/.src-hash) and rebuilds a
# cached .so whose stamp differs; the release tooling refuses a cache that
# carries no stamp or another one.  One script, so the two sides never
# disagree on what is hashed.
#
# The options and the recipes are in it because a change to either changes
# the binary as surely as a change to the source: while the hash covered the
# source alone, a fix made in the options left every cached .so "current".
cd "$(dirname "$0")/.." || exit 1
LC_ALL=C cat nginx-module/config nginx-module/hardening.sh \
    $(LC_ALL=C ls build-docker/*/build-one.sh) \
    $(LC_ALL=C ls nginx-module/src/*.c nginx-module/src/*.h | grep -v -E '_fuzz\.c$|_test\.c$') | sha256sum | cut -c1-16
