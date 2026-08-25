#!/bin/bash
# 60: the challenge page's ?_test_redirect= override must stay on-origin.
#
# It did not.  The guard read the first two characters of the value, and a URL
# parser strips TAB / CR / LF from anywhere in the input before parsing -- so
# "/<TAB>/evil.example" passed the character check and navigated to
# "//evil.example".  The branch is gated on being at the challenge / test path,
# not on a test flag, so it was reachable on any install by anyone who could
# get a visitor to complete one challenge.
#
# Found by CodeQL, not by this suite: every curl scenario re-implements the PoW
# and never runs the redirect.  Hence a browser scenario.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/browser.sh"

run_playwright_test redirect_guard.py \
    "the challenge redirect override stays on-origin and a legitimate path still works"
