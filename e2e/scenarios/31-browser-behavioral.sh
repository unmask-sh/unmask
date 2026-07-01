#!/bin/bash
# 31: a human-like browser must PASS the checkbox behavioral check and clear the
# challenge WITHOUT the math fallback -- the happy path most real visitors take,
# the counterpart to 28's fallback path.  Mouse movement + scroll + a keypress
# (automation flags hidden) drive the behavioral score over the threshold.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/browser.sh"

run_playwright_test behavioral_flow.py \
    "human-like browser passed the behavioral check (no math) and cleared it (200)"
