#!/bin/sh
# Print a short hash of the nginx module's source (nginx-module/config and the
# non-test .c / .h files).  The Makefile stamps every cached module .so with
# it (dist/multi-modules*/<nginx version>/.src-hash) and rebuilds a cached .so
# whose stamp differs; the release tooling refuses a cache that carries no
# stamp or another one.  One script, so the two sides never disagree on what
# is hashed.
cd "$(dirname "$0")/.." || exit 1
LC_ALL=C cat nginx-module/config $(LC_ALL=C ls nginx-module/src/*.c nginx-module/src/*.h | grep -v -E '_fuzz\.c$|_test\.c$') | sha256sum | cut -c1-16
