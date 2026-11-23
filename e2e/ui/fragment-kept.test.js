// A passed challenge keeps the fragment of the address it was shown at
// (2026-11-24).  A fragment -- a section of the page, a single-page app's
// route -- never reaches the server, and the page used to leave for the
// address without it: the visitor landed at the top of the page, or on the
// app's first screen.  Put back on the address it would load nothing (an
// address that differs from the page's own only in its fragment is a move
// within the page), so the page's own entry first takes an address that
// differs in its query too, and the page then loads, fragment and all.
//
// The page is served here by request interception at <origin>/__frag/page, as
// nginx would: the daemon's real challenge page (asked for with _orig, as
// protect.inc does) until the pass cookie is set, then a long page with an
// anchor half-way down.  Checked: a visit with a fragment lands on the address
// with it and at the anchor; a single-page app's route survives the same way;
// a visit without one leaves as it always did (no reload); and a visit from
// another site, which steps back to the entry it arrived on, keeps it too.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;
const SEARCH = 'http://search.test/';
const PAGE = ORIGIN + '/__frag/page?x=1';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// One visit in a fresh context: start(page) makes the first navigation.
async function visit(browser, name, start, target) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  // A plain Chrome name: the daemon sends a HeadlessChrome UA straight to the
  // CAPTCHA, and the proof of work is the path under test.
  const ua = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');
  await page.setUserAgent(ua);
  const seen = [];
  const errors = [];
  let land;
  const landed = new Promise(r => { land = r; });
  page.on('pageerror', e => errors.push(String(e)));
  await page.setRequestInterception(true);
  page.on('request', async req => {
    const u = req.url();
    try {
      if (u.startsWith(SEARCH)) {
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8', body:
          `<!doctype html><title>search</title><a id=go href="${target}">result</a>` });
      }
      if (new URL(u).pathname === '/__frag/page') {
        const orig = u.slice(ORIGIN.length);
        const passed = (await ctx.cookies()).some(c => c.name === '_bv' && c.value);
        if (!passed) {
          seen.push({ kind: 'challenge', url: u });
          const r = await fetch(BASE + '/challenge/?_orig=' + encodeURIComponent(orig), {
            headers: { 'Sec-Fetch-Dest': 'document', Accept: 'text/html', 'User-Agent': ua },
          });
          return req.respond({ status: 403, contentType: 'text/html; charset=utf-8',
            headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' }, body: await r.text() });
        }
        seen.push({ kind: 'page', url: u });
        land();
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8',
          headers: { 'Cache-Control': 'no-store' }, body:
          '<!doctype html><title>landed</title><body style="margin:0">' +
          '<div style="height:2400px">top</div><h2 id="sec2" style="margin:0;height:40px">two</h2>' +
          '<div style="height:2400px">bottom</div><script>window.__landed = { hash: location.hash, ' +
          'nav: (performance.getEntriesByType("navigation")[0] || {}).type };</script>' });
      }
      if (u.startsWith(ORIGIN + '/unmask/static/back.html')) seen.push({ kind: 'relay' });
      return req.continue();
    } catch (e) {
      errors.push('interception: ' + e);
      try { await req.continue(); } catch (_) {}
    }
  });

  await start(page);
  const arrived = await Promise.race([landed.then(() => true), new Promise(r => setTimeout(() => r(false), 30000))]);
  ok(arrived, `${name}: never reached the page; requests: ${JSON.stringify(seen)}`);
  let info = null;
  if (arrived) {
    await page.waitForFunction(() => window.__landed && document.readyState === 'complete', { timeout: 10000 }).catch(() => {});
    // The browser goes to the fragment once the page has loaded.
    await new Promise(r => setTimeout(r, 300));
    info = await page.evaluate(() => {
      const el = document.getElementById('sec2');
      return Object.assign({}, window.__landed, {
        href: location.href, y: Math.round(window.scrollY),
        top: el ? Math.round(el.getBoundingClientRect().top) : null,
      });
    }).catch(() => null);
  }
  return { ctx, seen, info, errors };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 800 },
  });
  const challenges = v => v.seen.filter(s => s.kind === 'challenge').length;
  const relays = v => v.seen.filter(s => s.kind === 'relay').length;

  // 1) A section of the page: the address keeps it, and the page is at it.
  let v = await visit(browser, 'a section', async p => { await p.goto(PAGE + '#sec2'); });
  ok(challenges(v) === 1, 'a section: challenged ' + challenges(v) + ' times: ' + JSON.stringify(v.seen));
  ok(v.info && v.info.hash === '#sec2' && v.info.href === PAGE + '#sec2',
    'a section: landed without the fragment: ' + JSON.stringify(v.info));
  ok(v.info && v.info.y > 1000 && Math.abs(v.info.top) < 5,
    'a section: the page is not at the anchor: ' + JSON.stringify(v.info));
  ok(v.info && v.info.nav === 'navigate', 'a section: the page did not load as a navigation: ' + JSON.stringify(v.info));
  ok(v.errors.length === 0, 'a section: ' + v.errors.join(' | '));
  await v.ctx.close();

  // 2) A single-page app's route: the address keeps it for the app to read.
  v = await visit(browser, 'an app route', async p => { await p.goto(PAGE + '#/settings/profile'); });
  ok(v.info && v.info.hash === '#/settings/profile', 'an app route: landed with ' + JSON.stringify(v.info));
  ok(v.errors.length === 0, 'an app route: ' + v.errors.join(' | '));
  await v.ctx.close();

  // 3) No fragment: the page leaves as it always did, not by a reload.
  v = await visit(browser, 'no fragment', async p => { await p.goto(PAGE); });
  ok(v.info && v.info.hash === '' && v.info.href === PAGE && v.info.nav === 'navigate',
    'no fragment: ' + JSON.stringify(v.info));
  ok(v.errors.length === 0, 'no fragment: ' + v.errors.join(' | '));
  await v.ctx.close();

  // 4) From another site: the pass steps back to the entry the visitor
  //    arrived on, and that entry's address carries the fragment.
  v = await visit(browser, 'from another site', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
  }, PAGE + '#sec2');
  ok(relays(v) === 1, 'from another site: the relay was asked for ' + relays(v) + ' times: ' + JSON.stringify(v.seen));
  ok(v.info && v.info.hash === '#sec2', 'from another site: landed with ' + JSON.stringify(v.info));
  ok(v.errors.length === 0, 'from another site: ' + v.errors.join(' | '));
  await v.ctx.close();

  await browser.close();
  if (fails.length) {
    for (const f of fails) console.error('FAIL: ' + f);
    process.exit(1);
  }
  console.log('ok: a passed challenge keeps the fragment of its address');
})().catch(e => { console.error(e); process.exit(1); });
