// "Preview" is the challenge page's own flag, read at its own addresses.
//
// The theme tab's previews load the page at /unmask/challenge/ (or a test
// page) with ?_preview=1: it then paints itself and stops, runs no
// proof-of-work, and takes a site name and a footer from its query.  nginx
// serves the same page in place of a visitor's page, where the path and the
// query are that page's.  A page whose URL said _preview=1 -- a CMS's draft
// link does -- left its visitor in front of a challenge that never ran; a
// page under a directory named /admin/test/ had the challenge show whatever
// site name and footer its link's query said; one under /test/ took the
// link's language.
//
// The visitor's page is served here by request interception at
// <origin>/__vis/..., as nginx would: the daemon's challenge page (asked for
// with _orig and then the page's own arguments, which is how nginx's rewrite
// hands them over) until the pass cookie is set, then the page.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const ORIGIN = new URL(BASE).origin;

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
// A step that never comes back ends the run with its name, not with the
// job's own time limit.
let step = 'start';
const watchdog = setTimeout(() => {
  console.error('FAIL preview-flag-visitor-page: stuck at "' + step + '"' + (fails.length ? '\n  ' + fails.join('\n  ') : ''));
  process.exit(1);
}, 150000);

// One visit to a page of the site, in a fresh context: what the challenge
// served in its place showed, and whether the visitor got to the page.
async function visit(browser, path) {
  step = 'visit ' + path;
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  // A plain Chrome name (the daemon sends a HeadlessChrome UA straight to
  // the CAPTCHA, and the proof-of-work is the pass here), and English as the
  // browser's language whatever this machine's is.
  const ua = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');
  await page.setUserAgent(ua);
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'language', { get: () => 'en-US' });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  });
  let landed = false, over = false;
  const errors = [];
  await page.setRequestInterception(true);
  page.on('request', async req => {
    // Once the visit is over nothing is asked of the context any more.
    if (over) { req.continue().catch(() => {}); return; }
    try {
      const u = new URL(req.url());
      // The page's beacons stay here: every address has a budget of them,
      // shared by the specs that run from this machine.
      if (u.pathname.indexOf('/api/debug') >= 0) return req.abort();
      if (u.origin === ORIGIN && u.pathname.indexOf('/__vis/') === 0) {
        const passed = (await ctx.cookies()).some(c => c.name === '_bv' && c.value);
        if (!passed) {
          const r = await fetch(BASE + '/challenge/?_orig=' + encodeURIComponent(u.pathname + u.search) +
            (u.search ? '&' + u.search.slice(1) : ''),
            { headers: { 'Sec-Fetch-Dest': 'document', Accept: 'text/html', 'User-Agent': ua } });
          return req.respond({ status: 403, contentType: 'text/html; charset=utf-8',
            headers: { 'Cache-Control': 'no-store' }, body: await r.text() });
        }
        landed = true;
        return req.respond({ status: 200, contentType: 'text/html; charset=utf-8',
          body: '<!doctype html><title>landed</title>landed' });
      }
      return req.continue();
    } catch (e) {
      errors.push('interception: ' + e);
      try { await req.continue(); } catch (_) {}
    }
  });
  step = 'visit ' + path + ': load';
  await page.goto(ORIGIN + path, { waitUntil: 'domcontentloaded' });
  step = 'visit ' + path + ': read what is shown';
  // The page's script is deferred: it has painted by now, and the pass is
  // most of a second away.
  const shown = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    text: document.body ? document.body.innerText : '',
    preview: !!(window.UNMASK && window.UNMASK._preview),
  })).catch(e => ({ err: String(e) }));
  step = 'visit ' + path + ': wait for the pass';
  for (let t0 = Date.now(); !landed && Date.now() - t0 < 30000;) await sleep(200);
  // The context is left to the browser's own close at the end: closed here,
  // with a request of the page still on its way through the handler above,
  // the close did not always come back.
  over = true;
  return { shown, landed, errors };
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 800 },
  });

  // The control: a page with an ordinary query is challenged and reached.
  let v = await visit(browser, '/__vis/article?id=7');
  ok(v.landed && !v.shown.preview, 'an ordinary page: reached=' + v.landed + ', shown ' + JSON.stringify(v.shown));

  // A page whose own query says _preview=1.
  v = await visit(browser, '/__vis/article?id=7&_preview=1');
  ok(!v.shown.preview, 'a page whose URL says _preview=1: the challenge in its place took itself for a preview');
  ok(v.landed, 'a page whose URL says _preview=1: the challenge never ran, the visitor never reached the page; it showed ' + JSON.stringify(v.shown.text));

  // A page under a directory named /admin/test/, whose link names a site
  // name and a footer.
  v = await visit(browser, '/__vis/admin/test/item?_preview_site_name=EVILNAME&_preview_footer_text=EVILFOOT');
  ok(!/EVILNAME|EVILFOOT/.test(v.shown.text || ''), 'a page under /admin/test/: the challenge shows the name or footer its link named: ' + JSON.stringify(v.shown.text));
  ok(v.landed, 'a page under /admin/test/: never reached');
  // The same with _preview=1 said too, and no admin page as the referrer.
  v = await visit(browser, '/__vis/article?_preview=1&_preview_site_name=EVILNAME&_preview_footer_text=EVILFOOT');
  ok(!/EVILNAME|EVILFOOT/.test(v.shown.text || '') && v.landed, 'a page whose URL says _preview=1 and names a site name: shown ' + JSON.stringify(v.shown.text) + ', reached=' + v.landed);

  // A page under a directory named /test/, whose link names a language.
  v = await visit(browser, '/__vis/test/item?_preview_lang=ja');
  ok(v.shown.lang === 'en', 'a page under /test/: the challenge took the language its link named (lang=' + v.shown.lang + ')');
  ok(v.landed, 'a page under /test/: never reached');

  // The theme tab's own preview is what it was: at the page's own address,
  // from an admin page, it stops and shows the name its query gives.
  const page = await browser.newPage();
  step = 'the theme tab\'s own preview';
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
  await page.goto(BASE + '/admin/settings/theme/', { waitUntil: 'networkidle2' });
  const frame = await page.evaluate(src => new Promise(resolve => {
    const f = document.createElement('iframe');
    f.onload = () => setTimeout(() => {
      const d = f.contentDocument, w = f.contentWindow;
      resolve({ text: d && d.body ? d.body.innerText : '', preview: !!(w.UNMASK && w.UNMASK._preview), path: w.location.pathname });
    }, 1500);
    f.src = src;
    document.body.appendChild(f);
  }), BASE + '/challenge/?_test_ja4=0&theme=dark&_preview=1&_preview_site_name=PreviewCo&_preview_lang=ja');
  ok(frame.preview && frame.path === '/unmask/challenge/', 'the theme tab\'s preview no longer stops as a preview: ' + JSON.stringify(frame));
  ok(/PreviewCo/.test(frame.text), 'the theme tab\'s preview no longer shows the site name its query gives: ' + JSON.stringify(frame.text.slice(0, 200)));
  ok(/[぀-ヿ]/.test(frame.text), 'the theme tab\'s preview no longer takes the language its query gives: ' + JSON.stringify(frame.text.slice(0, 200)));

  await browser.close();
  clearTimeout(watchdog);
  if (fails.length) {
    console.error('FAIL preview-flag-visitor-page:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok preview-flag-visitor-page');
})().catch(e => { console.error('ERROR preview-flag-visitor-page: ' + (e.stack || e)); process.exit(1); });
