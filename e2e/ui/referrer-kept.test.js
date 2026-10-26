// A passed challenge keeps where the visitor came from (2026-10-27).  The
// challenge page used to leave with location.replace, which made itself the
// referrer of the page it loaded: analytics counted a visit from a search or
// another site as direct.  It now steps back to the history entry the visitor
// arrived on (pushState + the relay page /unmask/static/back.html +
// history.back), and the browser fetches that entry again with its original
// Referer.
//
// The "original page" is served here by request interception at
// <origin>/__ref/page, as nginx would: the daemon's real challenge page (asked
// for with _orig, as protect.inc does) until the pass cookie is set, then the
// page.  The search page is another origin, also intercepted; the relay is
// the daemon's own.  Checked: a GET from another site steps back and lands
// with that site as the referrer (header and document.referrer), and Back
// then leaves to it; no referrer, an own-site referrer and a POST leave the
// old way; and a challenge that comes back right after a step back does not
// step back again -- it loaded as back_forward, and even reported as a fresh
// navigation, the relay still ahead in history leaves no room for a push.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;
const SEARCH = 'http://search.test/';
const PATH = '/__ref/page?x=1';
const PAGE = ORIGIN + PATH;

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// One visit in a fresh context.  start(page) makes the first navigation;
// times = how many requests for the page get the challenge (a second one
// stands for a challenge that comes back).
async function visit(browser, name, start, times = 1, before = null) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  if (before) await page.evaluateOnNewDocument(before);
  // A plain Chrome name: the daemon sends a HeadlessChrome UA straight to the
  // CAPTCHA, and the PoW is the path under test.
  const ua = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');
  await page.setUserAgent(ua);
  const seen = [];
  const errors = [];
  const consoleLines = [];
  let challenges = 0;
  let land;
  const landed = new Promise(r => { land = r; });
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => consoleLines.push(m.text()));
  await page.setRequestInterception(true);
  page.on('request', async req => {
    const u = req.url();
    try {
      if (u.startsWith(SEARCH)) {
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8', body:
          `<!doctype html><title>search</title><a id=go href="${PAGE}">result</a>` +
          `<form id=f method=post action="${PAGE}"><input name=q value=1><button id=post>post</button></form>` });
      }
      if (u === ORIGIN + '/__ref/start') {
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8', body:
          `<!doctype html><title>start</title><a id=go href="${PATH}">in-site link</a>` });
      }
      if (u === PAGE) {
        const referer = req.headers().referer || '';
        const passed = (await ctx.cookies()).some(c => c.name === '_bv' && c.value);
        if (!passed || challenges < times) {
          challenges++;
          seen.push({ kind: 'challenge', method: req.method(), referer });
          const r = await fetch(BASE + '/challenge/?_orig=' + encodeURIComponent(PATH), {
            method: req.method(),
            headers: { 'Sec-Fetch-Dest': 'document', Accept: 'text/html', 'User-Agent': ua },
            body: req.method() === 'POST' ? 'q=1' : undefined,
          });
          return req.respond({ status: 403, contentType: 'text/html; charset=utf-8',
            headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' }, body: await r.text() });
        }
        seen.push({ kind: 'page', method: req.method(), referer });
        land();
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8',
          headers: { 'Cache-Control': 'no-store' }, body:
          '<!doctype html><title>landed</title><body>landed<script>window.__landed = { ref: document.referrer, ' +
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
  if (!arrived) {
    const text = await page.evaluate(() => document.body && document.body.innerText.slice(0, 400)).catch(e => 'ERR ' + e);
    console.error(`${name}: stuck at ${page.url()} showing ${JSON.stringify(text)}; console ${JSON.stringify(consoleLines.slice(0, 8))}`);
  }
  ok(arrived, `${name}: never reached the page; requests: ${JSON.stringify(seen)}`);
  let info = null;
  if (arrived) {
    await page.waitForFunction(() => window.__landed, { timeout: 10000 }).catch(() => {});
    info = await page.evaluate(() => window.__landed).catch(() => null);
  }
  return { ctx, page, seen, info, errors, url: page.url() };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 800 },
  });
  const relays = v => v.seen.filter(s => s.kind === 'relay').length;
  const pages = v => v.seen.filter(s => s.kind === 'page');

  // 1) A GET from another site steps back and keeps the referrer.
  let v = await visit(browser, 'from another site', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
  });
  ok(relays(v) === 1, 'from another site: the relay was asked for ' + relays(v) + ' times: ' + JSON.stringify(v.seen));
  ok(pages(v).length === 1 && pages(v)[0].referer === SEARCH,
    'from another site: the page was fetched with Referer ' + JSON.stringify(pages(v).map(p => p.referer)));
  ok(v.info && v.info.ref === SEARCH, 'from another site: document.referrer is ' + JSON.stringify(v.info));
  ok(v.info && v.info.nav === 'back_forward', 'from another site: the page did not land by stepping back: ' + JSON.stringify(v.info));
  ok(v.url === PAGE, 'from another site: landed on ' + v.url);
  // Back leaves to the site the visitor came from: no copy of the page, no relay in between.
  await v.page.goBack().catch(() => {});
  ok(v.page.url() === SEARCH, 'from another site: Back went to ' + v.page.url());
  ok(v.errors.length === 0, 'from another site: ' + v.errors.join(' | '));
  await v.ctx.close();

  // 2) No referrer: nothing to keep, the old way.
  v = await visit(browser, 'no referrer', async p => { await p.goto(PAGE); });
  ok(relays(v) === 0, 'no referrer: stepped back anyway: ' + JSON.stringify(v.seen));
  ok(v.info && v.info.nav === 'navigate', 'no referrer: ' + JSON.stringify(v.info));
  await v.ctx.close();

  // 3) An own-site referrer: the old way.
  v = await visit(browser, 'own site', async p => {
    await p.goto(ORIGIN + '/__ref/start');
    await p.click('#go');
  });
  ok(relays(v) === 0, 'own site: stepped back anyway: ' + JSON.stringify(v.seen));
  await v.ctx.close();

  // 4) A POST: stepping back would ask to resend the form; the old way.
  v = await visit(browser, 'a POST', async p => {
    await p.goto(SEARCH);
    await p.click('#post');
  });
  ok(v.seen[0] && v.seen[0].method === 'POST', 'a POST: the first request was ' + JSON.stringify(v.seen[0]));
  ok(relays(v) === 0, 'a POST: stepped back anyway: ' + JSON.stringify(v.seen));
  ok(pages(v).length === 1 && pages(v)[0].method === 'GET', 'a POST: the page after the pass: ' + JSON.stringify(v.seen));
  await v.ctx.close();

  // 5) The challenge comes back after the step back: the second pass leaves
  //    the old way instead of going round again.
  v = await visit(browser, 'challenge again', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
  }, 2);
  ok(relays(v) === 1, 'challenge again: the relay was asked for ' + relays(v) + ' times: ' + JSON.stringify(v.seen));
  ok(v.seen.filter(s => s.kind === 'challenge').length === 2 && pages(v).length === 1,
    'challenge again: ' + JSON.stringify(v.seen));
  await v.ctx.close();

  // 6) The same, in a browser that reports the re-fetched entry as a fresh
  //    navigation: the relay is still ahead in history, so the push adds no
  //    entry and the page leaves the old way.
  v = await visit(browser, 'challenge again, fresh-looking', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
  }, 2, () => {
    const real = performance.getEntriesByType.bind(performance);
    performance.getEntriesByType = t => (t === 'navigation' ? [{ type: 'navigate' }] : real(t));
  });
  ok(relays(v) === 1, 'challenge again, fresh-looking: the relay was asked for ' + relays(v) + ' times: ' + JSON.stringify(v.seen));
  await v.ctx.close();

  await browser.close();
  if (fails.length) {
    console.error('FAIL referrer-kept:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok referrer-kept');
})().catch(e => { console.error('ERROR referrer-kept: ' + (e.stack || e)); process.exit(1); });
