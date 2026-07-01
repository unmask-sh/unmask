#!/bin/bash
# 29: a real headless browser must clear the challenge through FORWARD-AUTH mode
# (Apache + mod_lua), not just native mode (27).  Forward-auth is the advertised
# default mode; this drives a protected path on the e2e Apache, runs the actual
# challenge.js, solves the seed-bound PoW, and confirms the origin is reached.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/browser.sh"

run_playwright_test forward_auth_flow.py \
    "real browser cleared the Apache forward-auth challenge and reached the origin (200)"
