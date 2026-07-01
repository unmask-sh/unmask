#!/usr/bin/env bash
# run-fuzz.sh — build + run the libFuzzer harness for ja4_parse_client_hello.
#
# License: Apache 2.0 (clean-room implementation from JA4 specification)
#
# Usage:
#   ./run-fuzz.sh                 # 60 s quick run (= CI default)
#   ./run-fuzz.sh 300             # 5 min quick run
#   ./run-fuzz.sh long            # 24 h soak (= forwards to `make fuzz-long`)
#   FUZZ_CC=clang-17 ./run-fuzz.sh
#
# Exits non-zero on:
#   - clang missing                  (= rc 127)
#   - build failure                  (= rc forwarded from make)
#   - libFuzzer crash / leak / OOM   (= rc forwarded from libFuzzer)

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

if ! command -v "${FUZZ_CC:-clang}" >/dev/null 2>&1; then
  cat <<'EOF' >&2
ERROR: clang not found in PATH.

libFuzzer ships with clang; gcc cannot build the harness.  Install:

  RHEL/Rocky 9:   sudo dnf install clang
  Debian/Ubuntu:  sudo apt install clang
  Alpine 3.19+:   sudo apk add clang19 compiler-rt

Then re-run this script.  Alternatively use the gcc-only random sweep:

  cd ../../src
  gcc -fsanitize=address -O1 ja4_parser.c ja4_parser_fuzz.c -o /tmp/quickfuzz
  /tmp/quickfuzz 1000000
EOF
  exit 127
fi

case "${1:-}" in
  long)
    exec make fuzz-long
    ;;
  ""|[0-9]*)
    secs="${1:-60}"
    exec make fuzz FUZZ_TIME_QUICK="$secs"
    ;;
  *)
    echo "usage: $0 [<seconds>|long]" >&2
    exit 2
    ;;
esac
