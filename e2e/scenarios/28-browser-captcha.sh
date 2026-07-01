#!/bin/bash
# 28: a real headless browser must clear the math-CAPTCHA fallback end-to-end.
#
# This is the path the tool1-jp incident wedged real users on: 98.5% JA4=ok,
# every behavioral score null, all dropped to the numeric-add fallback, and 87%
# never cleared it.  Scenario 04 hits the captcha API directly; this runs the
# actual challenge.js UI (tick "I'm not a robot" -> headless fails the behavioral
# check -> math fallback -> solve a+b -> _bv -> pass) via the Playwright image.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/browser.sh"

run_playwright_test captcha_math_flow.py \
    "real browser cleared the math-CAPTCHA fallback and passed (200)"
