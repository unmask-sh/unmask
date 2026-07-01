#!/usr/bin/env python3
# Investigation aid for the scenario-28 regression: dump the exact behavioral
# Sig payload a headless Chromium POSTs to /api/verify and the score the server
# answers with, to see WHICH axes now pass.  Not part of the suite.
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443")
FORCE = "/unmask/test/force-captcha"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(ignore_https_errors=True, user_agent=UA,
                              extra_http_headers={"X-Forwarded-For": "198.51.100.99"})
    page = ctx.new_page()

    def on_request(req):
        if "/api/verify" in req.url and req.method == "POST":
            try:
                body = json.loads(req.post_data or "{}")
                print("VERIFY-REQ sig=" + json.dumps(body.get("sig"), sort_keys=True))
            except Exception as e:
                print("VERIFY-REQ parse error: %r" % e)

    def on_response(resp):
        if "/api/verify" in resp.url:
            try:
                print("VERIFY-RESP status=%d body=%s" % (resp.status, resp.text()))
            except Exception as e:
                print("VERIFY-RESP read error: %r" % e)

    page.on("request", on_request)
    page.on("response", on_response)

    page.goto(BASE + FORCE, wait_until="domcontentloaded")
    page.wait_for_selector("#notRobot", timeout=15000)
    page.check("#notRobot")
    page.wait_for_timeout(5000)  # let the verify round-trip + any fallback land

    math_visible = page.evaluate(
        "() => { var q=document.getElementById('mathQ');"
        " return !!(q && q.offsetParent !== null); }")
    print("MATH-FALLBACK-VISIBLE=%s" % math_visible)
    browser.close()
sys.exit(0)
