// A failed "send test" on the notifications tab says why (2026-10-26).  The
// webhook test answers 502 + JSON with the reason when the hook refuses, and
// nginx's fail-open used to swap that for its own plain-text 503 ("unmask
// admin temporarily unavailable"); the page then showed "SyntaxError:
// Unexpected token 'u'" instead of the reason.  The rendered config now lets
// the daemon's answer through (nginxconf's fail-open test pins that).  This
// drives the page: a dead hook's failure arrives with its reason and without
// the hook's token, and an answer that is not JSON -- the old nginx 503, a
// proxy's error page -- shows its status and words, on the webhook button and
// on the mail one beside it.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const net = require('net');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// A port nothing listens on: the hook's dial fails at once.
const deadPort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

(async () => {
  const port = await deadPort();
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"]'),
  ]);
  await page.goto(BASE + '/admin/settings/notifications/', { waitUntil: 'networkidle2' });

  // Click a test button and read its result once it has one.
  const press = async (btn, out) => {
    await page.$eval(out, el => { el.textContent = ''; });
    await page.click(btn);
    await page.waitForFunction(sel => {
      const t = document.querySelector(sel).textContent;
      return t !== '' && t !== '...';
    }, { timeout: 15000 }, out).catch(() => {});
    return page.$eval(out, el => el.textContent);
  };

  // 1) The daemon's own answer: the hook is dead.
  await page.$eval('#notify-form [name=url]', (el, u) => { el.value = u; },
    `http://127.0.0.1:${port}/services/T0/B0/hook-secret`);
  let got = await press('#notify-test-btn', '#notify-test-result');
  ok(/connection refused/.test(got), 'a dead hook\'s reason reaches the page: ' + got);
  ok(!/hook-secret/.test(got), 'the hook\'s token stays off the page: ' + got);

  // 2) An answer that is not JSON, as nginx's fail-open sent it.
  await page.setRequestInterception(true);
  page.on('request', req => {
    if (req.method() === 'POST' && /\/admin\/api\/(notify|smtp)\/test$/.test(req.url())) {
      return req.respond({ status: 503, contentType: 'text/plain', body: 'unmask admin temporarily unavailable\n' });
    }
    return req.continue();
  });
  got = await press('#notify-test-btn', '#notify-test-result');
  ok(/HTTP 503 unmask admin temporarily unavailable/.test(got) && !/SyntaxError/.test(got),
    'the webhook button shows a non-JSON answer\'s status and words: ' + got);
  got = await press('#smtp-test-btn', '#smtp-test-result');
  ok(/HTTP 503 unmask admin temporarily unavailable/.test(got) && !/SyntaxError/.test(got),
    'the mail button shows a non-JSON answer\'s status and words: ' + got);

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.error('FAIL notify-test-error:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok notify-test-error');
})().catch(e => { console.error('ERROR notify-test-error: ' + (e.stack || e)); process.exit(1); });
