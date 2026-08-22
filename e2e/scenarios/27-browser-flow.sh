#!/bin/bash
# 27: a real headless browser must solve the challenge end-to-end -- the only
# scenario that executes the actual challenge.js (the curl scenarios re-implement
# the PoW).  A stale/djb2 or otherwise-broken challenge.js (the web1-jp loop)
# can never pass here.  Runs via the official Playwright image; skips if docker /
# the image is unavailable.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/browser.sh"

run_playwright_test browser_flow.py \
    "real headless browser solved the seed-bound PoW end-to-end and passed (200)"
