// A CAPTCHA from an outside provider (Turnstile, hCaptcha, reCAPTCHA v3) ends
// with the daemon checking the provider's token.  When that check did not get
// the visitor through -- the daemon refused the token, could not reach the
// provider, or was not reached itself -- the card showed one line of text and
// nothing to act on: the token was spent, the widget still showed its tick,
// and the only move left was the browser's own reload, which nothing on the
// page named.
//
//   - a widget that can be reset (Turnstile, hCaptcha) is reset, and the
//     visitor solves it again -- twice at most;
//   - after that, and where there is nothing to reset (reCAPTCHA v3 scores
//     without asking), the card offers a reload button;
//   - a widget that failed to load or render gets the reload button too.
//
// No provider is contacted: the test answers the provider's script with a
// stand-in that records what the page asks of it, and answers the daemon's
// verify itself.  The pages are the site previews of three sites run.sh gives
// a provider each (challenge.sites in its config.yml).
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const pageOf = (site) => BASE + '/test/site/' + site + '/?_force=captcha';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// A test that hangs is a failed test, not a stuck run.
setTimeout(() => { console.error('ERROR provider-retry: timed out'); process.exit(1); }, 90000).unref();

// The provider's script, as far as the page uses it.  `widget` is 'ok' (the
// widget renders and waits to be solved) or 'error' (it calls the page's
// error callback instead).
const fakeTurnstile = (widget) => `
  window.__w = { renders: 0, resets: [], solve: null };
  window.turnstile = {
    render: function (el, opts) {
      window.__w.renders++;
      if (${JSON.stringify(widget)} === 'error') { setTimeout(function () { opts['error-callback']('110200'); }, 50); return 'w-ts'; }
      el.style.height = '65px'; el.textContent = '[turnstile]';
      window.__w.solve = opts.callback;
      return 'w-ts';
    },
    reset: function (id) { window.__w.resets.push(id); }
  };
  window._unmaskTurnstileCb();`;
const fakeHcaptcha = `
  window.__w = { renders: 0, resets: [], solve: null };
  window.hcaptcha = {
    render: function (el, opts) {
      window.__w.renders++;
      el.style.height = '78px'; el.textContent = '[hcaptcha]';
      window.__w.solve = opts.callback;
      return 'w-hc';
    },
    reset: function (id) { window.__w.resets.push(id); }
  };
  window._unmaskHcaptchaCb();`;
const fakeRecaptcha = `
  window.__w = { executes: 0 };
  window.grecaptcha = {
    ready: function (f) { f(); },
    execute: function () { window.__w.executes++; return Promise.resolve('tok-v3-' + window.__w.executes); }
  };
  window._unmaskRecaptchaCb();`;

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  let script = '';        // what the provider's script URL answers
  let verify = 'reject';  // how the daemon's verify answers
  const tokens = [];      // the provider tokens the page sent to verify
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const u = req.url();
    if (/^https:\/\/(challenges\.cloudflare\.com|js\.hcaptcha\.com|www\.google\.com)\//.test(u)) {
      return req.respond({ status: 200, contentType: 'application/javascript', body: script });
    }
    // Beacons are not this test's subject, and the address's budget is shared
    // with every other spec.
    if (req.method() === 'POST' && /\/api\/[^/]+\/debug$|\/api\/debug$/.test(u)) return req.abort('failed');
    if (req.method() === 'POST' && /\/verify$/.test(u)) {
      try { tokens.push(JSON.parse(req.postData() || '{}').provider_token || ''); } catch (_) { tokens.push('?'); }
      if (verify === 'reject') {
        return req.respond({ status: 403, contentType: 'application/json',
          body: JSON.stringify({ ok: 0, error: 'provider_rejected', provider: 'x', detail: 'invalid-input-response' }) });
      }
      if (verify === 'html503') {
        return req.respond({ status: 503, contentType: 'text/html', body: '<html><body>unavailable</body></html>' });
      }
      return req.abort('failed');
    }
    return req.continue();
  });

  const state = () => page.evaluate(() => {
    const shown = (id) => { const e = document.getElementById(id); return !!e && getComputedStyle(e).display !== 'none'; };
    const text = (id) => { const e = document.getElementById(id); return e ? e.textContent : ''; };
    return {
      err: shown('errMsg') ? text('errMsg') : '',
      widget: shown('extCaptcha'),
      reloadBox: shown('ctExpired'),
      reloadMsg: text('ctExpiredMsg'),
      reloadBtn: text('ctExpiredReload'),
      w: window.__w || null,
    };
  });
  const solve = async (tok) => { await page.evaluate((t) => window.__w.solve(t), tok); await sleep(700); };
  const open = async (site) => {
    await page.goto(pageOf(site), { waitUntil: 'networkidle0' });
    await page.waitForFunction(() => window.__w && (window.__w.renders > 0 || window.__w.executes > 0), { timeout: 15000 });
    await sleep(300);
  };

  // --- Turnstile: refused, reset, refused, reset, refused, reload ---------
  script = fakeTurnstile('ok'); verify = 'reject'; tokens.length = 0;
  await open('turnstile.ui-e2e.example');
  let s = await state();
  ok(s.widget && !s.reloadBox && s.w.renders === 1, 'Turnstile: the widget is on the card to begin with, got ' + JSON.stringify(s));

  await solve('tok-1');
  s = await state();
  ok(tokens.length === 1 && tokens[0] === 'tok-1', 'Turnstile: the token goes to the daemon, got ' + JSON.stringify(tokens));
  ok(s.err !== '', 'Turnstile, 1st refusal: the card says so, got ' + JSON.stringify(s));
  ok(s.w.resets.length === 1 && s.w.resets[0] === 'w-ts', 'Turnstile, 1st refusal: the widget is reset for another go, got ' + JSON.stringify(s.w));
  ok(s.widget && !s.reloadBox, 'Turnstile, 1st refusal: the widget stays, no reload offered yet, got ' + JSON.stringify(s));

  await solve('tok-2');
  s = await state();
  ok(tokens.length === 2 && s.w.resets.length === 2, 'Turnstile, 2nd refusal: reset once more, got ' + JSON.stringify([tokens, s.w]));
  ok(s.widget && !s.reloadBox, 'Turnstile, 2nd refusal: still the widget, got ' + JSON.stringify(s));

  await solve('tok-3');
  s = await state();
  ok(s.w.resets.length === 2, 'Turnstile, 3rd refusal: no third reset, got ' + JSON.stringify(s.w));
  ok(s.reloadBox && s.reloadBtn.trim() !== '' && s.reloadMsg.trim() !== '',
     'Turnstile, 3rd refusal: the card offers the reload with its text, got ' + JSON.stringify(s));
  ok(!s.widget && s.err === '', 'Turnstile, 3rd refusal: the spent widget and the bare line are gone, got ' + JSON.stringify(s));

  // The button reloads the page: a fresh challenge, a fresh widget.
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 15000 }),
    page.click('#ctExpiredReload'),
  ]);
  await page.waitForFunction(() => window.__w && window.__w.renders === 1, { timeout: 15000 });
  s = await state();
  ok(s.widget && !s.reloadBox && s.w.resets.length === 0, 'Turnstile: the reload brings a fresh widget, got ' + JSON.stringify(s));

  // --- the daemon is not reached, or does not answer as itself ------------
  verify = 'html503'; tokens.length = 0;
  await solve('tok-4');
  s = await state();
  ok(s.err.indexOf('(E-503)') >= 0, 'an answer that is not the daemon\'s keeps its code on the card, got ' + JSON.stringify(s.err));
  ok(s.w.resets.length === 1 && s.widget, '...and the widget is reset for another go, got ' + JSON.stringify(s));

  // --- hCaptcha: the same, through its own reset --------------------------
  script = fakeHcaptcha; verify = 'reject'; tokens.length = 0;
  await open('hcaptcha.ui-e2e.example');
  await solve('tok-h1');
  s = await state();
  ok(tokens[0] === 'tok-h1' && s.w.resets.length === 1 && s.w.resets[0] === 'w-hc' && s.widget && !s.reloadBox,
     'hCaptcha, refused: its widget is reset, got ' + JSON.stringify([tokens, s]));

  // --- reCAPTCHA v3: nothing to reset, so the reload at once --------------
  script = fakeRecaptcha; verify = 'reject'; tokens.length = 0;
  await page.goto(pageOf('recaptcha.ui-e2e.example'), { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => window.__w && window.__w.executes > 0, { timeout: 15000 });
  await sleep(900);
  s = await state();
  ok(tokens.length === 1 && tokens[0] === 'tok-v3-1', 'reCAPTCHA v3: its token goes to the daemon once, got ' + JSON.stringify(tokens));
  ok(s.reloadBox && s.w.executes === 1, 'reCAPTCHA v3, refused: the reload is offered, and no second token is drawn, got ' + JSON.stringify(s));

  // --- a widget that fails to render: the reload, with the widget's code --
  script = fakeTurnstile('error'); verify = 'reject'; tokens.length = 0;
  await page.goto(pageOf('turnstile.ui-e2e.example'), { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => window.__w && window.__w.renders > 0, { timeout: 15000 });
  await sleep(600);
  s = await state();
  ok(s.reloadBox && s.reloadMsg.indexOf('(E-WIDGET)') >= 0 && !s.widget,
     'a widget that errors: the card offers the reload and names the widget, got ' + JSON.stringify(s));
  ok(tokens.length === 0, 'a widget that errors sends nothing to the daemon, got ' + JSON.stringify(tokens));

  await browser.close();
  if (fails.length) {
    console.error('FAIL provider-retry:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok provider-retry');
})().catch(e => { console.error('ERROR provider-retry: ' + (e.stack || e)); process.exit(1); });
