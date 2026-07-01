#!/usr/bin/env python3
# The behavioral-success counterpart to scenario 28: a human-like browser (mouse
# movement + scroll + a keypress, automation flags hidden) must PASS the checkbox
# behavioral check and clear the challenge WITHOUT ever seeing the math fallback.
#
# This guards the "happy path" most real visitors take.  The tool1-jp incident
# showed every behavioral score coming back null (so everyone dropped to math);
# this asserts the behavioral path itself still issues a _bv for a real browser.
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443")
FORCE = "/unmask/test/force-captcha"
PROT = "/pow-gate/"
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
    # Dedicated XFF so browser scenarios don't share the host IP's rate-limit /
    # ban state with each other (the e2e proxies trust XFF).
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.82"})
    ctx.add_init_script(STEALTH)
    page = ctx.new_page()
    page.goto(BASE + FORCE, wait_until="domcontentloaded")
    page.wait_for_selector("#notRobot", state="attached", timeout=15000)

    # human-like signal: a moving mouse trail, a scroll, a keypress.
    for i in range(40):
        page.mouse.move(80 + i * 9, 140 + (i % 11) * 7)
        time.sleep(0.015)
    page.mouse.wheel(0, 250)
    page.keyboard.press("Tab")
    time.sleep(0.4)

    # tick the checkbox -> the behavioral check should pass and issue a _bv.  Use
    # click(), NOT check(): on the happy path ticking the box clears the challenge
    # and the page redirects to "/" instantly, so check()'s post-click "is it
    # checked?" verification races that navigation and times out (the element is
    # gone).  The real success signal is the _bv cookie wait just below.
    page.click("#notRobot")
    try:
        page.wait_for_function("() => document.cookie.indexOf('_bv=') !== -1", timeout=15000)
    except Exception:
        fail("behavioral check issued no _bv for a human-like browser")

    # the math fallback must NOT have been shown -- the behavioral path cleared it.
    # On success the challenge page redirects the instant the _bv is set, so this
    # evaluate can lose a race with the navigation ("execution context was
    # destroyed").  That is not a failure: reaching here means the _bv wait above
    # already succeeded, which only happens on the behavioral path (a math-gated
    # run never issues a _bv without solving the sum), so a navigated-away page is
    # itself proof the math gate never blocked us.  Treat a destroyed context as
    # "math not shown".
    try:
        math_shown = page.evaluate(
            "() => { var m=document.getElementById('mathFallback');"
            " return !!(m && m.offsetParent !== null); }")
    except Exception:
        math_shown = False
    if math_shown:
        fail("math fallback appeared despite human-like interaction (behavioral did not pass)")

    resp2 = ctx.request.get(BASE + PROT)
    if resp2.status != 200:
        fail("protected path returned %d after the behavioral pass" % resp2.status)

    print("PASS: human-like browser passed the behavioral check (no math) and cleared it (200)")
    browser.close()
