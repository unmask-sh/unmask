// A hunt row must say which Host it came from when that is not obvious.
//
// The badge used to be gated on `len(SitePickerOptions) > 1` -- a proxy for
// "this install has several sites".  In defined mode the picker lists only
// DECLARED sites, so an install that declared exactly one never showed the
// badge at all, which is the install where it matters most: the log still
// carries every Host the server answered.  Observed on unmask.sh, where 296
// scanner hits on the bare IP sat in the log with nothing naming the Host,
// under a setting labelled "display only the listed sites".
//
// run.sh seeds one record for an undeclared Host (203.0.113.77).
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/hunt/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);

  const res = await page.evaluate(() => {
    const row = document.querySelector('table.events tbody tr[data-site="203.0.113.77"]');
    if (!row) return { missing: true };
    const badge = row.querySelector('.site-badge');
    return {
      text: badge ? badge.textContent.trim() : null,
      ghost: badge ? badge.className.includes('site-ghost') : false,
    };
  });

  if (res.missing) {
    ok(false, 'the seeded undeclared-Host row is not on the page (seeding or range changed)');
  } else {
    ok(res.text === '203.0.113.77',
       `an undeclared Host must be named on its row, got ${JSON.stringify(res.text)}`);
    ok(res.ghost, 'an undeclared Host should be marked as a ghost, not styled like a declared site');
  }

  await browser.close();
  if (fails.length) { console.error('FAIL\n- ' + fails.join('\n- ')); process.exit(1); }
  console.log('site-badge: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
