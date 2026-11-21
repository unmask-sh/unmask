// The challenge script is a file beside the page, and a browser that cannot
// get the file is not left on a challenge that never runs.
//
// The page used to carry the script on every serve, because of that browser:
// with the script in a file it could not load -- an extension, a proxy, a
// connection that dropped, a node of another build answering for it -- it
// showed the challenge, ran nothing, and was challenged again for ever.  The
// script went into the page, and every client that runs no script at all was
// sent it too, at five times the size of the page.
//
// Now the page names the file (/unmask/static/challenge.<hash>.js, kept by the
// browser) and its own small script watches the load.  When the file fails or
// nothing has started after a wait, it sets the _bvi cookie and loads the page
// again, and the daemon answers that request with the script inside the page:
// what it always sent.  It asks once: a page that still names the file while
// the cookie is set was not heard, and says it cannot run.  A file that
// arrived and did not start -- rewritten on the way, or a browser too old
// for it -- is asked for the same way, without the wait.
//
// The daemon serves the file to requests that came through the module's
// nginx, which it knows by the header server.inc sets (X-Unmask-Local-Port);
// this instance has no nginx in front, so the browser sends the header.  Each
// way the file can fail is produced by answering its request here.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const http = require('http');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;
const LANDING = '/unmask/healthz?after=the-challenge';
const CHALLENGE = BASE + '/challenge/?_orig=' + encodeURIComponent(LANDING) + '&_return=' + encodeURIComponent(LANDING);
const VIA_MODULE = { 'X-Unmask-Local-Port': '443' };
const FILE = /^\/unmask\/static\/challenge\.[0-9a-f]{16}\.js$/;

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const state = () => ({
  path: location.pathname,
  started: !!window.__unmaskStarted,
  inline: window.UNMASK ? window.UNMASK.js_inline : null,
  fileTag: !!document.getElementById('unmask-js'),
  asked: /(?:^|;\s*)_bvi=1/.test(document.cookie),
  msg: document.getElementById('msg') ? document.getElementById('msg').textContent : null,
  spinner: (() => { const s = document.getElementById('spinner'); return s ? getComputedStyle(s).display : null; })(),
});

// get: the page as the daemon serves it to a browser's navigation with these
// headers and no cookie.  (fetch would name itself a script's request, and
// the daemon answers those in JSON.)
function get(url, headers) {
  return new Promise((resolve, reject) => {
    http.get(url, { headers: Object.assign({ Accept: 'text/html', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate' }, headers) }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', d => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
}

// until: poll the page for a state, through the reload the page may make
// (an evaluate that lands in the middle of one throws, and is asked again).
async function until(page, want, ms) {
  const end = Date.now() + ms;
  let st = null;
  while (Date.now() < end) {
    try { st = await page.evaluate(state); if (want(st)) return st; } catch (e) {}
    await sleep(100);
  }
  return st;
}

// A page in a context of its own, with a plain Chrome name (the daemon sends
// a HeadlessChrome UA straight to the CAPTCHA, and the proof of work is the
// pass here) and the module's header.  file(req) answers the file's request;
// doc(req) may answer the page's.  The page's beacons stay here: every
// address has a budget of them, shared by the specs run from this machine.
async function open(browser, { file, doc, cookie }) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  await page.setUserAgent((await browser.userAgent()).replace('HeadlessChrome', 'Chrome'));
  await page.setExtraHTTPHeaders(VIA_MODULE);
  if (cookie) await ctx.setCookie({ name: '_bvi', value: '1', domain: new URL(BASE).hostname, path: '/' });
  const seen = { docs: 0, files: 0, errors: [] };
  page.on('pageerror', e => seen.errors.push(String(e)));
  await page.setRequestInterception(true);
  page.on('request', req => {
    const u = new URL(req.url());
    if (u.origin !== ORIGIN) return req.abort();
    if (u.pathname.indexOf('/api/debug') >= 0) return req.abort();
    if (req.resourceType() === 'document' && /^\/unmask\/challenge\/?$/.test(u.pathname)) {
      seen.docs++;
      if (doc) return doc(req);
    }
    if (FILE.test(u.pathname)) {
      seen.files++;
      return file(req);
    }
    return req.continue();
  });
  return { ctx, page, seen };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1200, height: 800 },
  });
  const UA = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');

  // 1. The file arrives: the page is the page alone, the script runs from the
  //    file, the challenge is passed -- and the next page takes the file from
  //    the browser's cache.  No interception here: it would switch the cache
  //    off.  The beacons are held back by address instead.
  {
    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();
    await page.setUserAgent(UA);
    await page.setExtraHTTPHeaders(VIA_MODULE);
    const cdp = await page.createCDPSession();
    await cdp.send('Network.enable');
    await cdp.send('Network.setBlockedURLs', { urls: ['*/unmask/api/debug*'] });
    const files = [];
    const violations = [];
    page.on('response', r => {
      if (FILE.test(new URL(r.url()).pathname)) {
        const h = r.headers();
        files.push({ status: r.status(), cache: h['cache-control'], enc: h['content-encoding'] || '', type: h['content-type'] || '', fromCache: r.fromCache() });
      }
    });
    page.on('console', m => { if (/Content Security Policy/i.test(m.text())) violations.push(m.text()); });
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));

    const resp = await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const html = await resp.text();
    ok(resp.status() === 403, '1: the challenge answers 403, got ' + resp.status());
    ok(/<script nonce="[^"]+" id="unmask-js" src="\/unmask\/static\/challenge\.[0-9a-f]{16}\.js" defer><\/script>/.test(html),
      '1: the page names the script\'s file');
    ok(html.indexOf('_bv_set_ok') < 0, '1: the page does not carry the script as well');
    ok(html.length < 45000, '1: the page without the script is ' + html.length + ' bytes');
    const landed = await until(page, s => s.path === '/unmask/healthz', 30000);
    ok(landed && landed.path === '/unmask/healthz', '1: the script from the file passes the challenge, got ' + JSON.stringify(landed));
    ok((await ctx.cookies()).some(c => c.name === '_bv' && c.value), '1: the pass cookie is set');
    ok(!(await ctx.cookies()).some(c => c.name === '_bvi'), '1: nothing asked for the script inside the page');
    ok(files.length === 1 && files[0].status === 200, '1: the file was fetched once, got ' + JSON.stringify(files));
    if (files.length) {
      ok(files[0].cache === 'public, max-age=31536000, immutable', '1: the file is one to keep, got ' + files[0].cache);
      ok(files[0].enc === 'gzip', '1: the daemon compresses the file itself, got ' + JSON.stringify(files[0].enc));
      ok(/javascript/.test(files[0].type), '1: served as a script, got ' + files[0].type);
    }
    ok(violations.length === 0, '1: the page\'s policy refused something: ' + violations.join(' | '));
    ok(errors.length === 0, '1: page errors: ' + errors.join(' | '));

    files.length = 0;
    await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const again = await until(page, s => s.started || s.path === '/unmask/healthz', 15000);
    ok(again && (again.started || again.path === '/unmask/healthz'), '1: the second page runs too, got ' + JSON.stringify(again));
    ok(files.length === 1 && files[0].fromCache, '1: the second page takes the file from the browser\'s cache, got ' + JSON.stringify(files));
  }

  // 2. The file does not arrive (the connection fails): the page asks for
  //    itself with the script inside, once, and that page passes.
  {
    const { ctx, page, seen } = await open(browser, { file: req => req.abort('failed') });
    await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const st = await until(page, s => s.inline === 1 && s.started, 8000);
    ok(st && st.inline === 1 && st.started, '2: the page came back with the script inside and ran it, got ' + JSON.stringify(st));
    ok(st && st.asked && !st.fileTag, '2: by the cookie, and the page names no file now, got ' + JSON.stringify(st));
    const landed = await until(page, s => s.path === '/unmask/healthz', 30000);
    ok(landed && landed.path === '/unmask/healthz', '2: the page with the script inside passes the challenge, got ' + JSON.stringify(landed));
    ok(seen.docs === 2 && seen.files === 1, '2: one page that named the file, one with the script inside; got ' + JSON.stringify(seen));
    ok((await ctx.cookies()).some(c => c.name === '_bv' && c.value), '2: the pass cookie is set');
  }

  // 3. The file is not this node's (another build answers 404): the same way
  //    back.
  {
    const { page, seen } = await open(browser, {
      file: req => req.respond({ status: 404, contentType: 'text/plain; charset=utf-8', headers: { 'Cache-Control': 'no-store' }, body: '404 page not found\n' }),
    });
    await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const st = await until(page, s => s.inline === 1 && s.started, 8000);
    ok(st && st.inline === 1 && st.started && st.asked, '3: a 404 for the file brings the page with the script inside, got ' + JSON.stringify(st));
    ok(seen.docs === 2, '3: asked once, got ' + JSON.stringify(seen));
  }

  // 4. The file arrives and is not the script (something on the way rewrote
  //    it; a browser too old to parse it sees the same): the page with the
  //    script inside is asked for at once, not after the wait.  (What the old
  //    browser is then told is old-browser-guard.test.js.)
  {
    const { page, seen } = await open(browser, {
      file: req => req.respond({ status: 200, contentType: 'application/javascript; charset=utf-8', body: '(async function(){ ]' }),
    });
    const t0 = Date.now();
    await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const st = await until(page, s => s.inline === 1 && s.started, 5000);
    ok(st && st.inline === 1 && st.started && st.asked, '4: a file that is not the script brings the page with the script inside, got ' + JSON.stringify(st));
    ok(Date.now() - t0 < 5000, '4: without the ten seconds, took ' + (Date.now() - t0) + ' ms');
    ok(seen.docs === 2, '4: asked once, got ' + JSON.stringify(seen));
  }

  // 5. The cookie is set and the page still names the file: the request was
  //    not heard (the cookie did not reach the daemon).  The page says it
  //    cannot run; it does not load itself for ever.  Produced by answering
  //    the page's request with the page the daemon serves a browser without
  //    the cookie.
  {
    const { page, seen } = await open(browser, {
      cookie: true,
      file: req => req.abort('failed'),
      doc: async (req) => {
        try {
          const res = await get(req.url(), Object.assign({ 'User-Agent': UA }, VIA_MODULE));
          ok(/id="unmask-js"/.test(res.body), '5: the daemon serves the page that names the file to a request without the cookie');
          return req.respond({
            status: res.status,
            contentType: 'text/html; charset=utf-8',
            headers: { 'Content-Security-Policy': res.headers['content-security-policy'] || '' },
            body: res.body,
          });
        } catch (e) { return req.abort('failed'); }
      },
    });
    await page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' });
    const st = await until(page, s => s.msg && s.msg.indexOf('cannot display this page') >= 0, 3000);
    ok(st && st.msg && st.msg.indexOf('cannot display this page') >= 0, '5: not heard, the page says it cannot run, got ' + JSON.stringify(st));
    await sleep(1500);
    ok(seen.docs === 1, '5: and does not load itself again, got ' + JSON.stringify(seen));
  }

  // 6. The file never answers: after the wait, the same way back.  (Ten
  //    seconds; the page with the script inside waits five for its own.)
  {
    const { page, seen } = await open(browser, { file: () => { /* left unanswered */ } });
    const t0 = Date.now();
    // Not awaited: the file's tag is deferred, and a deferred script that has
    // not arrived holds the document's DOMContentLoaded back with it.
    page.goto(CHALLENGE, { waitUntil: 'domcontentloaded' }).catch(() => {});
    let st = await until(page, s => s.inline === 1, 6000);
    ok(st && st.inline === 0 && st.fileTag, '6: six seconds in, the page still waits for the file (giving up sooner would load everything twice on a slow connection), got ' + JSON.stringify(st));
    st = await until(page, s => s.inline === 1 && s.started, 12000);
    ok(st && st.inline === 1 && st.started && st.asked, '6: a file that never answers brings the page with the script inside, got ' + JSON.stringify(st) + ' after ' + (Date.now() - t0) + ' ms');
    ok(seen.docs === 2, '6: asked once, got ' + JSON.stringify(seen));
  }

  // Contexts are left to the browser's close: closing one whose requests are
  // still held does not always return.
  await browser.close();
  if (fails.length) {
    console.error('FAIL challenge-script-file:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok challenge-script-file');
})().catch(e => { console.error('ERROR challenge-script-file: ' + (e.stack || e)); process.exit(1); });

// A run that hangs must not hold the suite: the whole spec is well under two
// minutes.
setTimeout(() => { console.error('ERROR challenge-script-file: still running after 150 s'); process.exit(1); }, 150000).unref();
