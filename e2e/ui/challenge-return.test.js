// Where a pass on /unmask/challenge/ goes: the page named by _return.
//
// nginx serves the challenge at the page's own address, and a pass loads the
// page in its place.  A dispatcher that cannot -- the Apache snippet answers
// the request with a redirect -- leaves the browser at /unmask/challenge/, and
// a pass there used to land on the site's top page, whatever the visitor had
// asked for.  The snippet now names the page as _return, and the challenge
// page goes there: on this origin only, and never back into the challenge.
//
// _orig alone still lands on the top page.  It carries the same URL from the
// Apache snippet, but it is also what the JSON answer to an API call puts in
// its challenge_url, naming the API's path, which is not a page to load.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const enc = encodeURIComponent;

// One pass in a fresh context: the challenge page asked for with query, the
// PoW solved by the page itself, and where the browser is once it has left.
async function pass(browser, query) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  // A plain Chrome name: the daemon sends a HeadlessChrome UA straight to the
  // CAPTCHA, and the PoW is the pass under test.
  await page.setUserAgent((await browser.userAgent()).replace('HeadlessChrome', 'Chrome'));
  const offSite = [];
  await page.setRequestInterception(true);
  page.on('request', req => {
    const u = new URL(req.url());
    if (u.origin !== ORIGIN) { offSite.push(req.url()); req.abort(); return; }
    // The page's beacons stay here: every address has a budget of them,
    // shared by the specs that run from this machine, and these visits say
    // nothing the suite reads.
    if (u.pathname.indexOf('/api/debug') >= 0) { req.abort(); return; }
    req.continue();
  });
  let landed = null;
  try {
    await page.goto(BASE + '/challenge/?' + query, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => !/^\/unmask\/challenge\/?$/.test(location.pathname), { timeout: 30000 });
    landed = page.url();
  } catch (e) {
    // An aborted off-site navigation leaves the page where it was; what was
    // asked for is in offSite.
    landed = offSite.length ? 'off-site: ' + offSite[0] : 'never left the challenge (' + e.message.split('\n')[0] + ')';
  }
  await ctx.close();
  return { landed, offSite };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1200, height: 800 },
  });

  // The page asked for, query and all.
  const page = '/unmask/healthz?x=1&y=a%20b';
  let r = await pass(browser, '_orig=' + enc(page) + '&_return=' + enc(page));
  ok(r.landed === ORIGIN + page, '_return: the pass lands on the page asked for, got ' + r.landed);

  // _orig without _return: the top page, as before.
  r = await pass(browser, '_orig=' + enc('/unmask/healthz'));
  ok(r.landed === ORIGIN + '/', '_orig alone: the pass lands on the top page, got ' + r.landed);

  // Never off this origin, however the value is spelled; the top page then.
  for (const v of ['https://evil.example/', '//evil.example/', '/\t/evil.example']) {
    r = await pass(browser, '_return=' + enc(v));
    ok(r.offSite.length === 0 && r.landed === ORIGIN + '/', `_return=${JSON.stringify(v)}: stays on this origin's top page, got ${r.landed}`);
  }

  // Never back into the challenge or a test page: that is another challenge
  // on every pass.
  for (const v of ['/unmask/challenge/?_return=%2Funmask%2Fchallenge%2F', '/unmask/test/force-pow']) {
    r = await pass(browser, '_return=' + enc(v));
    ok(r.landed === ORIGIN + '/', `_return=${v}: the top page, not this page again, got ${r.landed}`);
  }

  // The test override, where both are given, is the one that counts.
  r = await pass(browser, '_test_redirect=' + enc('/unmask/healthz?t=1') + '&_return=' + enc('/unmask/healthz?r=1'));
  ok(r.landed === ORIGIN + '/unmask/healthz?t=1', '_test_redirect beside _return: the override wins, got ' + r.landed);

  await browser.close();
  if (fails.length) {
    console.error('FAIL challenge-return:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok challenge-return');
})().catch(e => { console.error('ERROR challenge-return: ' + (e.stack || e)); process.exit(1); });
