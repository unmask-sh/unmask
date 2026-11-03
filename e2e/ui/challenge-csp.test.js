// The challenge page carries a Content-Security-Policy of its own and runs
// under it without a violation: its two inline scripts and the inlined
// challenge.js by the serve's nonce, the proof-of-work in a blob: worker,
// the CAPTCHA card's scripts, and the step-back relay's one script.
//
// A violation is silent on the page -- the worker falls back to the slow
// UI-thread loop, a blocked inline script leaves the spinner -- and shows
// only in the console, so that is what this reads.
//
// The challenge page is not the admin, so this test does not log in; it
// drives /unmask/test/force-pow and force-captcha, which run.sh enables on
// the throwaway instance.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const violation = (m) => /Content.Security.Policy|Refused to/i.test(m);

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });

  for (const kind of ['pow', 'captcha']) {
    const page = await browser.newPage();
    const console_ = [];
    page.on('console', m => console_.push(m.text()));
    page.on('pageerror', e => console_.push('pageerror: ' + e));
    // The PoW page's pass would leave for "/"; the beacons and the /bvj
    // issue are POSTs the test does not need.
    await page.setRequestInterception(true);
    page.on('request', q => (q.method() === 'POST' ? q.abort() : q.continue()));
    const res = await page.goto(BASE + '/test/force-' + kind, { waitUntil: 'domcontentloaded' });
    const csp = res.headers()['content-security-policy'] || '';
    const m = /'nonce-([^']+)'/.exec(csp);
    ok(m !== null, kind + ': the page carries a policy with a nonce, got ' + JSON.stringify(csp));
    if (m) {
      const tagged = await page.evaluate((n) => {
        let c = 0;
        for (const s of document.querySelectorAll('script')) if (s.nonce === n || s.getAttribute('nonce') === n) c++;
        return { count: c, started: !!window.__unmaskStarted, inWindow: window.UNMASK && window.UNMASK.csp_nonce };
      }, m[1]);
      ok(tagged.count >= 3, kind + ': the inline scripts carry the nonce, got ' + JSON.stringify(tagged));
      ok(tagged.started, kind + ': the challenge script ran under the policy');
      ok(tagged.inWindow === m[1], kind + ': window.UNMASK carries the nonce for the scripts the page adds');
    }
    ok(/worker-src blob:/.test(csp), kind + ': the policy allows the proof-of-work worker');
    if (kind === 'pow') {
      // Let the worker solve (or fail to start): a refused worker logs a
      // violation; the solve itself ends in a navigation the POST block
      // does not stop, so wait only as long as a solve takes.
      await sleep(3000).catch(() => {});
    } else {
      await page.waitForSelector('#notRobot', { timeout: 10000 });
      await sleep(500);
    }
    const bad = console_.filter(violation);
    ok(bad.length === 0, kind + ': no policy violation in the console, saw ' + JSON.stringify(bad.slice(0, 3)));
    await page.close().catch(() => {});
  }

  // The relay page: its script runs under its own nonce and sends the
  // visitor on (to "/" here: nothing to step back to).
  const relay = await browser.newPage();
  const lines = [];
  relay.on('console', m => lines.push(m.text()));
  const res = await relay.goto(BASE + '/static/back.html', { waitUntil: 'domcontentloaded' }).catch(() => null);
  const csp = res ? (res.headers()['content-security-policy'] || '') : '';
  ok(/'nonce-/.test(csp), 'relay: the relay carries a nonced policy, got ' + JSON.stringify(csp));
  await sleep(800);
  ok(lines.filter(violation).length === 0, 'relay: no violation, saw ' + JSON.stringify(lines.slice(0, 3)));
  ok(!/\/static\/back\.html/.test(relay.url()), 'relay: the relay script ran and left the page, still at ' + relay.url());
  await relay.close().catch(() => {});

  await browser.close();
  if (fails.length) {
    console.error('FAIL challenge-csp:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok challenge-csp');
})().catch(e => { console.error('ERROR challenge-csp: ' + (e.stack || e)); process.exit(1); });
