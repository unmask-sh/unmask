#!/usr/bin/env python3
# Drive the FULL challenge in a real headless browser -- the only e2e that runs
# the actual challenge.js (the curl scenarios re-implement the PoW).  A stale or
# broken challenge.js (the web1-jp loop) can never pass here.
#
# challenge.js flags a plain headless browser as a bot (navigator.webdriver +
# zero plugins => flags>=3) and routes it to the CAPTCHA path, never the PoW.
# This test targets the PoW *solving* path, so we present as an ordinary browser
# (webdriver off, plugins present); the bot heuristics themselves are covered by
# the curl honeypot/JA4 scenarios.
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443")
PROT = "/pow-gate/"  # a PoW-only protected path (see e2e admin.yml) a browser can auto-clear
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
STEALTH = (
    "Object.defineProperty(navigator,'webdriver',{get:()=>false});"
    "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3]});"
)


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


with sync_playwright() as p:
    browser = p.chromium.launch()
    # A dedicated XFF so the browser scenarios don't share the host IP's
    # rate-limit / ban state with each other (the e2e proxies trust XFF).
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.80"})
    ctx.add_init_script(STEALTH)
    page = ctx.new_page()

    # 1. Hit a PoW-only protected path -> the plugin serves the challenge (403).
    resp = page.goto(BASE + PROT, wait_until="domcontentloaded")
    if not resp or resp.status != 403:
        fail("expected a challenge (403), got %s" % (resp.status if resp else None))

    # 2. The real challenge.js must solve the seed-bound PoW and set the _bv.
    try:
        page.wait_for_function("() => document.cookie.indexOf('_bv=') !== -1", timeout=30000)
    except Exception:
        fail("challenge.js did not set a _bv within 30s (PoW unsolved? stale/djb2 JS?)")

    # 3. The protected path must now pass (200), reusing the browser's cookies.
    resp2 = ctx.request.get(BASE + PROT)
    if resp2.status != 200:
        fail("protected path returned %d after solving -- re-challenge loop" % resp2.status)

    print("PASS: real browser solved the seed-bound PoW and passed (200)")
    browser.close()
