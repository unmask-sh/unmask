// The challenge page reaches a browser compressed by the daemon.
//
// nginx compresses a page it proxies only where the operator turned gzip on
// (and, behind a load balancer, said gzip_proxied), and a 403 at that, never
// the 429 of a rate limit.  Where it does not, the page went out at three
// times the size it needs, mostly to clients that run no script.  So the
// daemon compresses it for a client that reads gzip, when the request came
// through the module's nginx -- which it knows by the header server.inc sets
// (X-Unmask-Local-Port); this instance has no nginx in front, so the browser
// sends the header.
//
// What has to hold in a real browser: the compressed page is the page -- it
// draws, its script starts and the challenge is passed -- both as the page
// that names the script's file and as the larger one with the script inside.
//
// The operator's switch is last: Settings > Challenge has a box, ticked where
// nothing is said, that hands nginx the page as it is when unticked (for an
// nginx that compresses it smaller, or rewrites it on the way out).
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN,
// UI_E2E_SHOT_DIR.
const http = require('http');
const path = require('path');
const zlib = require('zlib');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const LANDING = '/unmask/healthz?after=the-compressed-challenge';
const CHALLENGE = BASE + '/challenge/?_orig=' + encodeURIComponent(LANDING) + '&_return=' + encodeURIComponent(LANDING);
const VIA_MODULE = { 'X-Unmask-Local-Port': '443' };

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const state = () => ({
  path: location.pathname,
  started: !!window.__unmaskStarted,
  inline: window.UNMASK ? window.UNMASK.js_inline : null,
});

async function until(page, want, ms) {
  const end = Date.now() + ms;
  let st = null;
  while (Date.now() < end) {
    try { st = await page.evaluate(state); if (want(st)) return st; } catch (e) {}
    await sleep(100);
  }
  return st;
}

// raw: the answer as it is on the wire -- status, headers and the bytes of
// the body, nothing decoded -- for a navigation with these headers.
function raw(url, headers) {
  return new Promise((resolve, reject) => {
    http.get(url, { headers: Object.assign({ Accept: 'text/html', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate' }, headers) }, res => {
      const parts = [];
      res.on('data', d => parts.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
    }).on('error', reject);
  });
}

// visit: a browser of its own goes to the challenge, as through the module.
// Says how the page came (the document's status and encoding, and what the
// wire carried against what the browser read) and whether it passed.
async function visit(browser, UA, n, { cookie }) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  await page.setUserAgent(UA);
  await page.setExtraHTTPHeaders(VIA_MODULE);
  if (cookie) await ctx.setCookie({ name: '_bvi', value: '1', domain: new URL(BASE).hostname, path: '/' });
  const cdp = await page.createCDPSession();
  await cdp.send('Network.enable');
  await cdp.send('Network.setBlockedURLs', { urls: ['*/unmask/api/debug*'] });
  let docId = null;
  const doc = { wire: 0 };
  cdp.on('Network.responseReceived', e => {
    if (e.type === 'Document' && docId === null && /\/unmask\/challenge\//.test(e.response.url)) {
      docId = e.requestId;
      doc.status = e.response.status;
      doc.enc = (e.response.headers['content-encoding'] || e.response.headers['Content-Encoding'] || '');
      doc.vary = (e.response.headers['vary'] || e.response.headers['Vary'] || '');
    }
  });
  cdp.on('Network.loadingFinished', e => { if (e.requestId === docId) doc.wire = e.encodedDataLength; });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  const resp = await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
  const html = await resp.text();
  const st = await until(page, s => s.started || s.path === '/unmask/healthz', 15000);
  const landed = await until(page, s => s.path === '/unmask/healthz', 30000);
  ok(doc.status === 403, n + ': the challenge answers 403, got ' + doc.status);
  ok(doc.enc === 'gzip', n + ': the page comes compressed (Content-Encoding gzip), got ' + JSON.stringify(doc.enc));
  ok(/accept-encoding/i.test(doc.vary), n + ': and says it varies with Accept-Encoding, got ' + JSON.stringify(doc.vary));
  ok(/<\/html>\s*$/.test(html), n + ': what the browser decoded is a whole page (' + html.length + ' bytes)');
  ok(st && (st.started || st.path === '/unmask/healthz'), n + ': the page\'s script started, got ' + JSON.stringify(st));
  ok(landed && landed.path === '/unmask/healthz', n + ': and the challenge is passed, got ' + JSON.stringify(landed));
  ok((await ctx.cookies()).some(c => c.name === '_bv' && c.value), n + ': the pass cookie is set');
  ok(errors.length === 0, n + ': page errors: ' + errors.join(' | '));
  return { html, wire: doc.wire };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1200, height: 800 },
  });
  const UA = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');

  // 1. The page that names the script's file.
  {
    const { html, wire } = await visit(browser, UA, '1', {});
    ok(/id="unmask-js"/.test(html) && html.indexOf('_bv_set_ok') < 0, '1: the page names the script\'s file');
    // The wire figure includes the headers of the answer (under 2 KB).
    ok(wire > 0 && wire < html.length * 0.55, '1: ' + wire + ' bytes on the wire for a page of ' + html.length);
  }

  // 2. The page with the script inside, as sent to a browser that asked.
  {
    const { html, wire } = await visit(browser, UA, '2', { cookie: true });
    ok(html.indexOf('_bv_set_ok') >= 0 && !/id="unmask-js"/.test(html), '2: the page carries the script');
    ok(wire > 0 && wire < html.length * 0.55, '2: ' + wire + ' bytes on the wire for a page of ' + html.length);
  }

  // 3. On the wire, asked for and not: the same page either way, and the
  //    429 of a rate limit like the 403.
  {
    const gz = await raw(CHALLENGE, Object.assign({ 'User-Agent': UA, 'Accept-Encoding': 'gzip, deflate, br' }, VIA_MODULE));
    const plain = await raw(CHALLENGE, Object.assign({ 'User-Agent': UA }, VIA_MODULE));
    ok(gz.headers['content-encoding'] === 'gzip', '3: asked with gzip, the answer is gzip; got ' + JSON.stringify(gz.headers['content-encoding']));
    ok(!plain.headers['content-encoding'], '3: not asked, the answer is the page as it is; got ' + JSON.stringify(plain.headers['content-encoding']));
    let decoded = '';
    try { decoded = zlib.gunzipSync(gz.body).toString('utf8'); } catch (e) { ok(false, '3: the body does not decode: ' + e); }
    ok(Math.abs(decoded.length - plain.body.toString('utf8').length) <= 64,
      '3: decoded, it is the size of the page as it is (' + decoded.length + ' and ' + plain.body.length + ')');
    ok(Number(gz.headers['content-length']) === gz.body.length, '3: Content-Length is what was sent');
    const outside = await raw(CHALLENGE, { 'User-Agent': UA, 'Accept-Encoding': 'gzip' });
    ok(!outside.headers['content-encoding'] && !outside.headers['vary'],
      '3: a request that did not come through the module is answered as before; got ' + JSON.stringify({ enc: outside.headers['content-encoding'], vary: outside.headers['vary'] }));
    const rl = await raw(BASE + '/_rl/docs/', Object.assign({ 'User-Agent': UA, 'Accept-Encoding': 'gzip' }, VIA_MODULE));
    ok(rl.status === 429 && rl.headers['content-encoding'] === 'gzip',
      '3: the page of a rate limit (429) is compressed too; got ' + rl.status + ' ' + JSON.stringify(rl.headers['content-encoding']));
  }

  // 4. The operator's switch, on the settings page.
  {
    const page = await browser.newPage();
    await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', USER);
    await page.type('input[name="password"]', PASS);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.click('button[type="submit"], input[type="submit"]'),
    ]);
    const BOX = 'input[type="checkbox"][name="challenge_page_gzip"]';
    const set = async (on) => {
      await page.goto(BASE + '/admin/settings/challenge/', { waitUntil: 'networkidle2' });
      const shown = await page.$eval(BOX, e => e.checked).catch(() => null);
      if (shown === null) return null;
      if (shown !== on) await page.click(BOX);
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2' }),
        page.evaluate(sel => {
          const form = document.querySelector(sel).closest('form');
          Array.from(form.querySelectorAll('button[type="submit"]')).find(b => !b.hasAttribute('formaction')).click();
        }, BOX),
      ]);
      return shown;
    };
    const encoding = async () => (await raw(CHALLENGE, Object.assign({ 'User-Agent': UA, 'Accept-Encoding': 'gzip' }, VIA_MODULE))).headers['content-encoding'] || '';

    const before = await set(false);
    ok(before === true, '4: the box is on the challenge tab, ticked on an install that never set it; got ' + JSON.stringify(before));
    ok((await encoding()) === '', '4: with the box unticked the page leaves the daemon as it is; got ' + JSON.stringify(await encoding()));
    const kept = await set(true);
    ok(kept === false, '4: the saved box is shown unticked when the tab is opened again; got ' + JSON.stringify(kept));
    ok((await encoding()) === 'gzip', '4: with the box ticked again the page is compressed; got ' + JSON.stringify(await encoding()));
    await page.goto(BASE + '/admin/settings/challenge/', { waitUntil: 'networkidle2' });
    ok((await page.$eval(BOX, e => e.checked).catch(() => null)) === true, '4: and the box is shown ticked');
    // The field with its help open, for a look by eye.
    if (process.env.UI_E2E_SHOT_DIR) {
      try {
        await page.setViewport({ width: 1200, height: 900 });
        await page.$eval('#ch-page-gzip', e => e.scrollIntoView({ block: 'center' }));
        await page.click('#ch-page-gzip .ua-help-trigger');
        await sleep(400);
        await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'challenge-page-gzip-setting.png') });
      } catch (e) {}
    }
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL challenge-page-gzip:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok challenge-page-gzip');
})().catch(e => { console.error('ERROR challenge-page-gzip: ' + (e.stack || e)); process.exit(1); });

// A run that hangs must not hold the suite.
setTimeout(() => { console.error('ERROR challenge-page-gzip: still running after 150 s'); process.exit(1); }, 150000).unref();
