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
// A query the URL parser would write differently (a %20, a slash, a bare
// flag) reaches the page as the link had it, both ways.  The relay paints
// what the challenge page showed (challenge.js lookNow) where it showed it,
// and drops a value that would fetch something; a pass through the CAPTCHA
// hands over the card under its lines.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;
const SEARCH = 'http://search.test/';
const PATH = '/__ref/page?x=1';
const PAGE = ORIGIN + PATH;
// A query URLSearchParams would re-serialize: %20 -> +, / -> %2F, flag -> flag=.
const ODD = ORIGIN + '/__ref/page?u=/a&q=a%20b&flag';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// One visit in a fresh context.  start(page) makes the first navigation;
// times = how many requests for the page get the challenge (a second one
// stands for a challenge that comes back).
async function visit(browser, name, start, times = 1, before = null, target = PAGE, captcha = false) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  if (before) await page.evaluateOnNewDocument(before);
  // A plain Chrome name: the daemon sends a HeadlessChrome UA straight to the
  // CAPTCHA, and the PoW is the path under test -- unless the CAPTCHA is.
  const real = await browser.userAgent();
  const ua = captcha ? real : real.replace('HeadlessChrome', 'Chrome');
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
          `<!doctype html><title>search</title><a id=go href="${target}">result</a>` +
          `<form id=f method=post action="${target}"><input name=q value=1><button id=post>post</button></form>` });
      }
      if (u === ORIGIN + '/__ref/start') {
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8', body:
          `<!doctype html><title>start</title><a id=go href="${PATH}">in-site link</a>` });
      }
      if (new URL(u).pathname === '/__ref/page') {
        const referer = req.headers().referer || '';
        const orig = u.slice(ORIGIN.length);
        const passed = (await ctx.cookies()).some(c => c.name === '_bv' && c.value);
        if (!passed || challenges < times) {
          challenges++;
          seen.push({ kind: 'challenge', method: req.method(), referer, url: u });
          const r = await fetch(BASE + '/challenge/?_orig=' + encodeURIComponent(orig), {
            method: req.method(),
            headers: { 'Sec-Fetch-Dest': 'document', Accept: 'text/html', 'User-Agent': ua },
            body: req.method() === 'POST' ? 'q=1' : undefined,
          });
          return req.respond({ status: 403, contentType: 'text/html; charset=utf-8',
            headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' }, body: await r.text() });
        }
        seen.push({ kind: 'page', method: req.method(), referer, url: u });
        land();
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8',
          headers: { 'Cache-Control': 'no-store' }, body:
          '<!doctype html><title>landed</title><body>landed<script>window.__landed = { ref: document.referrer, ' +
          'nav: (performance.getEntriesByType("navigation")[0] || {}).type, ' +
          'mark: sessionStorage.getItem("unmask_back") };</script>' });
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
  // ... and what the challenge page showed, for the relay to paint.
  const look = v.info && v.info.mark && JSON.parse(v.info.mark).look;
  const kinds = look && Array.isArray(look.parts) ? look.parts.map(p => p.k) : [];
  ok(look && look.bg && kinds.includes('spin') && kinds.includes('text') &&
    look.parts.some(p => p.k === 'text' && p.t && p.w > 0 && p.y > 0),
    'from another site: the challenge left no look for the relay: ' + JSON.stringify(look));
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

  // 7) A query the URL parser would write differently keeps its form: the
  //    step back still happens, and the page gets the URL the link had.
  v = await visit(browser, 'odd query', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
  }, 1, null, ODD);
  ok(relays(v) === 1, 'odd query: the relay was asked for ' + relays(v) + ' times: ' + JSON.stringify(v.seen));
  ok(pages(v).length === 1 && pages(v)[0].url === ODD && pages(v)[0].referer === SEARCH,
    'odd query: the page was fetched as ' + JSON.stringify(pages(v)));
  ok(v.url === ODD, 'odd query: landed on ' + v.url);
  await v.ctx.close();

  // 8) ... and the old way, with no referrer to keep, loads that same URL.
  v = await visit(browser, 'odd query, no referrer', async p => { await p.goto(ODD); }, 1, null, ODD);
  ok(relays(v) === 0, 'odd query, no referrer: stepped back anyway: ' + JSON.stringify(v.seen));
  ok(pages(v).length === 1 && pages(v)[0].url === ODD,
    'odd query, no referrer: the page was fetched as ' + JSON.stringify(pages(v)));
  await v.ctx.close();

  // 9) The relay paints the look it is handed, where it was, and drops what
  //    would fetch something.  Its target answers 204, so it stays to be read.
  {
    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();
    await page.setRequestInterception(true);
    page.on('request', req => {
      const u = req.url();
      if (u === ORIGIN + '/__ref/start') return req.respond({ status: 200, contentType: 'text/html', body: '<!doctype html><title>start</title>' });
      if (u === ORIGIN + '/__ref/hold') return req.respond({ status: 204, body: '' });
      return req.continue();
    });
    await page.goto(ORIGIN + '/__ref/start');
    await page.evaluate(() => sessionStorage.setItem('unmask_back', JSON.stringify({ to: '/__ref/hold', t: Date.now(), look: {
      bg: 'rgb(1, 2, 3)', bgi: 'url(https://example.invalid/x.png)', title: 'Security check', lang: 'ar', dir: 'rtl',
      parts: [
        { k: 'box', x: 250, y: 150, w: 300, h: 200, c: 'rgb(255, 255, 255)', br: '12px', sh: 'rgba(0, 0, 0, 0.08) 0px 2px 12px 0px', bw: '0px', bs: 'none', bc: 'rgb(0, 0, 0)' },
        { k: 'spin', x: 380, y: 170, w: 40, h: 40, c: 'rgb(10, 20, 30)', r: 'rgb(40, 50, 60)', bw: '4px' },
        { k: 'text', x: 290, y: 226, w: 220, h: 48, t: 'Loading the site...', st: { color: 'rgb(7, 8, 9)', fontSize: '16px', lineHeight: '24px',
          fontWeight: '400', fontFamily: 'sans-serif', textAlign: 'center', wordBreak: 'keep-all', direction: 'rtl', position: 'fixed' } },
        { k: 'img', x: 0, y: 0, w: 10, h: 10, src: 'javascript:alert(1)' },
        { k: 'text', x: 0, y: 0, w: 10, h: 10, t: 'x', st: { color: 'url(https://example.invalid/y)' } },
      ] } })));
    await page.goto(ORIGIN + '/unmask/static/back.html');
    await new Promise(r => setTimeout(r, 300));
    const got = await page.evaluate(() => {
      if (!document.body) return { url: location.pathname, body: false, colors: [] };
      const divs = [...document.body.querySelectorAll('div')];
      const text = divs.find(d => d.textContent === 'Loading the site...');
      const spin = divs.find(d => d.style.animation.includes('unmask-spin'));
      const card = divs.find(d => d.style.borderRadius === '12px');
      const r = text && text.getBoundingClientRect(), cr = card && card.getBoundingClientRect();
      return { url: location.pathname, bg: getComputedStyle(document.body).backgroundColor, bgi: getComputedStyle(document.body).backgroundImage,
        title: document.title, lang: document.documentElement.lang, dir: document.documentElement.dir, imgs: document.images.length,
        text: text && { x: r.left, y: r.top, w: r.width, color: getComputedStyle(text).color,
          wb: getComputedStyle(text).wordBreak, pos: getComputedStyle(text).position, dir: getComputedStyle(text).direction },
        spin: spin && getComputedStyle(spin).borderTopColor, colors: divs.map(d => d.style.color),
        card: card && { x: cr.left, y: cr.top, w: cr.width, h: cr.height, bg: getComputedStyle(card).backgroundColor, under: divs.indexOf(card) < divs.indexOf(text) } };
    });
    ok(got.url === '/unmask/static/back.html', 'relay paint: the relay did not stay: ' + JSON.stringify(got));
    ok(got.bg === 'rgb(1, 2, 3)' && got.bgi === 'none', 'relay paint: background ' + JSON.stringify(got));
    ok(got.title === 'Security check' && got.lang === 'ar' && got.dir === 'rtl', 'relay paint: title / lang / dir ' + JSON.stringify(got));
    ok(got.text && got.text.x === 290 && got.text.y === 226 && got.text.w === 220 && got.text.color === 'rgb(7, 8, 9)',
      'relay paint: the text is not where it was: ' + JSON.stringify(got));
    // The type comes along, how it breaks included; a property off the list does not.
    ok(got.text && got.text.wb === 'keep-all' && got.text.dir === 'rtl' && got.text.pos === 'absolute', 'relay paint: the type ' + JSON.stringify(got));
    ok(got.spin === 'rgb(10, 20, 30)', 'relay paint: spinner ' + JSON.stringify(got));
    ok(got.card && got.card.x === 250 && got.card.y === 150 && got.card.w === 300 && got.card.h === 200 &&
      got.card.bg === 'rgb(255, 255, 255)' && got.card.under, 'relay paint: the CAPTCHA card ' + JSON.stringify(got));
    ok(got.imgs === 0 && !got.colors.some(c => /url/.test(c)), 'relay paint: a value that fetches was kept: ' + JSON.stringify(got));
    await ctx.close();
  }

  // 10) Through the CAPTCHA: the look handed to the relay starts with the
  //     card, under the "verified" lines.
  v = await visit(browser, 'captcha', async p => {
    await p.goto(SEARCH);
    await p.click('#go');
    await p.waitForSelector('#notRobot', { visible: true, timeout: 15000 });
    await p.click('#notRobot');
    const math = await p.waitForSelector('#mathFallback', { visible: true, timeout: 8000 }).catch(() => null);
    if (math) {
      await p.waitForFunction(() => /\d+ \+ \d+/.test(document.getElementById('mathQ').textContent), { timeout: 8000 });
      const [a, b] = (await p.$eval('#mathQ', e => e.textContent)).match(/\d+/g).map(Number);
      await p.type('#answerInput', String(a + b), { delay: 80 });
      await p.click('#submitBtn');
    }
  }, 1, null, PAGE, true);
  const clook = v.info && v.info.mark && JSON.parse(v.info.mark).look;
  const ck = clook && Array.isArray(clook.parts) ? clook.parts.map(p => p.k) : [];
  ok(relays(v) === 1 && pages(v).length === 1 && pages(v)[0].referer === SEARCH,
    'captcha: did not step back: ' + JSON.stringify(v.seen));
  ok(ck[0] === 'box' && ck.includes('spin') && clook.parts.some(p => p.k === 'text' && /^✓/.test(p.t)) &&
    ck.filter(k => k === 'text').length >= 3, 'captcha: the look is not the card with its lines: ' + JSON.stringify(clook));
  // The spinner's own size, not the box of the turned square.
  const cspin = clook && clook.parts.find(p => p.k === 'spin');
  ok(cspin && cspin.w === 40 && cspin.h === 40 && Number.isFinite(cspin.a), 'captcha: spinner ' + JSON.stringify(cspin));
  await v.ctx.close();

  await browser.close();
  if (fails.length) {
    console.error('FAIL referrer-kept:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok referrer-kept');
})().catch(e => { console.error('ERROR referrer-kept: ' + (e.stack || e)); process.exit(1); });
