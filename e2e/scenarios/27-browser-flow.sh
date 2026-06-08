#!/bin/bash
# 27: a real headless browser must solve the challenge end-to-end -- the only
# scenario that executes the actual challenge.js (the curl scenarios re-implement
# the PoW).  A stale/djb2 or otherwise-broken challenge.js (the tool1-jp loop)
# can never pass here.  Runs via the official Playwright image so no host install
# is needed; skips if docker / the image is unavailable.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

if ! command -v docker >/dev/null 2>&1; then
    log "SKIP: docker not available (need the Playwright image to drive a real browser)"
    exit 0
fi

IMG="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright/python:v1.49.0-jammy}"
if ! docker image inspect "$IMG" >/dev/null 2>&1 && ! docker pull "$IMG" >/dev/null 2>&1; then
    log "SKIP: Playwright image $IMG unavailable (set PLAYWRIGHT_IMAGE or pre-pull it)"
    exit 0
fi

# The python image ships the browsers under /ms-playwright but not the pip
# module, so install it (matching the image's browser build) and run against the
# cached browsers.  --network host lets the container reach the compose's nginx
# on localhost:8443.
PV="${PLAYWRIGHT_VERSION:-1.49.0}"
out=$(docker run --rm --network host -e BASE_URL="$BASE_URL" -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    -v "$DIR/lib/browser_flow.py:/t/browser_flow.py:ro" \
    "$IMG" sh -c "pip install -q playwright==$PV >/dev/null 2>&1 && python3 /t/browser_flow.py" 2>&1)
rc=$?
printf '%s\n' "$out" | sed 's/^/    /'
assert_eq 0 "$rc" "real headless browser solved the seed-bound PoW end-to-end and passed (200)"
