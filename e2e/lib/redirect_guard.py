#!/usr/bin/env python3
# The challenge page's ?_test_redirect= override must not send a visitor
# off-site.
#
# It used to.  The guard was three character checks -- starts with "/", second
# character is not "/" and not "\" -- which reads as exhaustive and is not: a
# URL parser removes TAB, CR and LF from anywhere in the input BEFORE parsing,
# so "/<TAB>/evil.example" passes a check on the string as written and is then
# navigated as "//evil.example".  Protocol-relative, off-site, on any install --
# the branch is gated on being at the challenge / test path, not on a test flag.
#
# The fix resolves the value against location.origin and compares origins, which
# is the only form that agrees with the navigation that follows.  A character
# check is a prediction about what the parser will do; asking the parser is not.
#
# This runs the real challenge.js in a real browser because that is the only
# place the bug existed -- it was invisible to every curl scenario, and it took
# static analysis to notice at all.  The point of the test is that the next one
# does not need to.
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443")
# /unmask/test/force-pow is a PoW challenge whose own pathname matches the
# branch under test (/^\/unmask\/(admin\/)?test(\/|$)/), which a protected
# path like /pow-gate/ does not -- a challenge served AT the protected path
# takes the other branch and never reads _test_redirect at all.  That is why
# the first draft of this test proved nothing.  e2e admin.yml sets
# public_test_pages: true, as scenarios 28 and 31 already rely on.
CHALLENGE = "/unmask/test/force-pow"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
STEALTH = (
    "Object.defineProperty(navigator,'webdriver',{get:()=>false});"
    "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3]});"
)

# Each of these resolves off-site once a URL parser has had it, whatever it
# looks like as a string.
OFF_SITE = [
    "/%09/evil.example",   # TAB   -> //evil.example
    "/%0a/evil.example",   # LF    -> //evil.example
    "/%0d/evil.example",   # CR    -> //evil.example
    "//evil.example",      # the shape the old guard did catch
    "/%5cevil.example",    # backslash: an authority separator to a browser
    "https://evil.example/",
]

failures = []


def check(page, ctx, value, expect_path):
    """Solve a challenge with ?_test_redirect=<value>, return the landing URL."""
    page.goto(BASE + CHALLENGE + "?_test_redirect=" + value,
              wait_until="domcontentloaded")
    try:
        page.wait_for_function(
            "() => location.pathname.indexOf('/unmask/test') !== 0", timeout=30000)
    except Exception:
        # No navigation at all is a pass for the hostile cases only if the page
        # never verified; treat it as inconclusive rather than silently green.
        return None
    return page.url


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.81"})
    ctx.add_init_script(STEALTH)
    page = ctx.new_page()

    for value in OFF_SITE:
        landed = check(page, ctx, value, None)
        if landed is None:
            failures.append("%s: the challenge never completed, so nothing was proven" % value)
        elif not landed.startswith(BASE):
            failures.append("%s: left the origin -- landed on %s" % (value, landed))

    # Positive control.  Without it the test passes whenever the redirect stops
    # working at all, which is the failure mode a security check invites.
    landed = check(page, ctx, "/pow-gate/", "/pow-gate/")
    if landed is None:
        failures.append("the override never redirected; the hostile cases prove nothing")
    elif not landed.startswith(BASE + "/pow-gate"):
        failures.append("a legitimate same-origin override was dropped: landed on %s" % landed)

    browser.close()

if failures:
    print("FAIL: " + "; ".join(failures))
    sys.exit(1)
print("PASS: the challenge redirect override stays on-origin (%d hostile values), "
      "and a legitimate path still redirects" % len(OFF_SITE))
