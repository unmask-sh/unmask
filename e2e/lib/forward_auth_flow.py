#!/usr/bin/env python3
# Drive the full challenge in a real headless browser through FORWARD-AUTH mode
# (the e2e Apache + mod_lua + apache-forward-auth.conf), not native mode.
#
# Forward-auth is the package's advertised default mode, yet the browser path was
# only ever exercised in native mode (scenario 27).  This navigates a protected
# path on Apache -> mod_lua subrequest to /api/check -> 302 to the challenge ->
# challenge.js solves the seed-bound PoW -> re-request clears it and Apache
# serves the origin.  A challenge.js that misbehaves only under forward-auth
# (different redirect / cookie handling) would fail here, not in 27.
import os
import sys

from playwright.sync_api import sync_playwright

APACHE = os.environ.get("APACHE_URL", "http://localhost:8081")
PROT = "/pow-gate/"  # a PoW-only protected path the forward-auth checker challenges
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
# Present as a normal browser so flags<3 routes to the PoW path, not bot/CAPTCHA.
STEALTH = (
    "Object.defineProperty(navigator,'webdriver',{get:()=>false});"
    "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3]});"
)


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


with sync_playwright() as p:
    browser = p.chromium.launch()
    # Dedicated XFF so browser scenarios don't share the host IP's rate-limit /
    # ban state with each other (Apache trusts XFF via mod_remoteip).
    ctx = browser.new_context(user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.83"})
    ctx.add_init_script(STEALTH)
    page = ctx.new_page()

    # 1. hit a protected path through Apache forward-auth -> 302 -> challenge page.
    page.goto(APACHE + PROT, wait_until="domcontentloaded")

    # 2. challenge.js must solve the seed-bound PoW and set the _bv.
    try:
        page.wait_for_function("() => document.cookie.indexOf('_bv=') !== -1", timeout=30000)
    except Exception:
        fail("challenge.js set no _bv within 30s under forward-auth (PoW unsolved?)")

    # 3. the protected path must now clear the forward-auth check and reach the
    #    Apache origin (200), reusing the browser's cookies.
    resp2 = ctx.request.get(APACHE + PROT)
    if resp2.status != 200:
        fail("forward-auth path returned %d after solving -- re-challenge loop" % resp2.status)
    body = resp2.text()
    if "unmask e2e apache backend" not in body:
        fail("expected the Apache origin after solving, got: %r" % body[:120])

    print("PASS: real browser cleared the Apache forward-auth challenge and reached the origin (200)")
    browser.close()
