#!/usr/bin/env python3
# Drive the math-CAPTCHA fallback in a real headless browser -- the exact path
# the tool1-jp incident wedged real users on (98.5% JA4=ok, behavioral score
# null for everyone, all dropped to the numeric-add fallback, 87% never cleared
# it).  The curl scenario 04 hits the captcha API directly; this runs the actual
# challenge.js UI: click "I'm not a robot" -> headless fails the behavioral check
# -> the math fallback appears -> solve a+b -> _bv -> pass.
import os
import re
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443")
FORCE = "/unmask/test/force-captcha"  # forces the CAPTCHA chmode (public_test_pages)
PROT = "/pow-gate/"                   # a protected path to confirm the issued _bv passes
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


with sync_playwright() as p:
    browser = p.chromium.launch()
    # Dedicated XFF so browser scenarios don't share the host IP's rate-limit /
    # ban state with each other (the e2e proxies trust XFF).
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.81"})
    page = ctx.new_page()

    # force-captcha serves the CAPTCHA challenge regardless of the global chmode.
    page.goto(BASE + FORCE, wait_until="domcontentloaded")

    # 1. tick the built-in "I'm not a robot" checkbox.
    page.wait_for_selector("#notRobot", timeout=15000)
    page.check("#notRobot")

    # 2. a headless browser fails the behavioral check, so the numeric-add
    #    fallback must appear with a real "a + b = ?" question.
    try:
        page.wait_for_function(
            "() => { var q=document.getElementById('mathQ');"
            " return q && q.offsetParent !== null && /\\d+\\s*\\+\\s*\\d+/.test(q.textContent); }",
            timeout=20000)
    except Exception:
        fail("math fallback did not appear (headless should fail the behavioral check)")

    q = page.text_content("#mathQ") or ""
    m = re.search(r"(\d+)\s*\+\s*(\d+)", q)
    if not m:
        fail("could not parse the math question: %r" % q)
    ans = int(m.group(1)) + int(m.group(2))

    # 3. solve it and submit.
    page.fill("#answerInput", str(ans))
    page.click("#submitBtn")

    # 4. the math answer must issue a _bv and clear the challenge.
    try:
        page.wait_for_function("() => document.cookie.indexOf('_bv=') !== -1", timeout=15000)
    except Exception:
        fail("math CAPTCHA accepted no _bv (solve path broken)")

    resp2 = ctx.request.get(BASE + PROT)
    if resp2.status != 200:
        fail("protected path returned %d after the math CAPTCHA -- not passing" % resp2.status)

    print("PASS: real browser solved the math-CAPTCHA fallback and passed (200)")
    browser.close()
