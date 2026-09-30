// Browser-level check of the pass-cookie reuse cap's card on the rate-limit tab.
// Against a real running admin (real templates + the save handler), verifies:
//   - the card ships on, with the seeds (10,000 a day / 2,000 at once) as
//     placeholders and captcha_only preselected,
//   - enabling it with values and deny survives a save (and the save lands
//     back on the rate-limit tab, with the reload banner: the zone renders),
//   - switching it off sticks, and the default comes back (the test leaves the
//     config as found).
//
// Driven by run.sh (throwaway admin). Env: UI_E2E_BASE, UI_E2E_USER,
// UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

async function card(page) {
  return page.evaluate(() => {
    const q = (n) => document.querySelector('[name="' + n + '"]');
    return {
      present: !!document.getElementById('rl-reuse'),
      enabled: q('reuse_enabled') ? q('reuse_enabled').checked : null,
      perDay: q('reuse_per_day') ? q('reuse_per_day').value : null,
      perDayPh: q('reuse_per_day') ? q('reuse_per_day').placeholder : null,
      burst: q('reuse_burst') ? q('reuse_burst').value : null,
      burstPh: q('reuse_burst') ? q('reuse_burst').placeholder : null,
      action: q('reuse_action') ? q('reuse_action').value : null,
      banner: (document.querySelector('.banner.ok') || {}).textContent || '',
      path: location.pathname,
    };
  });
}

async function save(page) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action*="section=rate_limit"] button[type="submit"]'),
  ]);
}

async function fill(page, v) {
  await page.evaluate((v) => {
    const q = (n) => document.querySelector('[name="' + n + '"]');
    q('reuse_enabled').checked = v.enabled;
    q('reuse_per_day').value = v.perDay;
    q('reuse_burst').value = v.burst;
    q('reuse_action').value = v.action;
  }, v);
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/settings/rate-limit/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/rate-limit/ status ${resp.status()}`);
  const first = await card(page);
  ok(first.present, 'the reuse cap card is missing');
  ok(first.enabled === true, 'the cap must ship on');
  ok(first.perDay === '' && first.perDayPh === '10000', `per day: value "${first.perDay}", placeholder "${first.perDayPh}"`);
  ok(first.burst === '' && first.burstPh === '2000', `at once: value "${first.burst}", placeholder "${first.burstPh}"`);
  ok(first.action === 'captcha_only', `default action: ${first.action}`);

  await fill(page, { enabled: true, perDay: '20000', burst: '3000', action: 'deny' });
  await save(page);
  const on = await card(page);
  ok(/\/settings\/rate-limit\/$/.test(on.path), `the save landed on ${on.path}, not the rate-limit tab`);
  ok(on.enabled === true && on.perDay === '20000' && on.burst === '3000' && on.action === 'deny',
    `after the save: ${JSON.stringify(on)}`);
  ok(on.banner.includes('nginx -s reload'), `turning the cap on renders a zone, so the banner asks for a reload: ${on.banner.trim()}`);

  await fill(page, { enabled: false, perDay: '', burst: '', action: 'captcha_only' });
  await save(page);
  const off = await card(page);
  ok(off.enabled === false && off.perDay === '' && off.burst === '',
    `switched off: ${JSON.stringify(off)}`);
  // Back to the untouched default: on, blank, captcha_only.
  await fill(page, { enabled: true, perDay: '', burst: '', action: 'captcha_only' });
  await save(page);
  const back = await card(page);
  ok(back.enabled === true && back.perDay === '' && back.burst === '' && back.action === 'captcha_only',
    `back to the default: ${JSON.stringify(back)}`);

  ok(errors.length === 0, `page error(s): ${errors.join(' | ')}`);
  await browser.close();
  if (fails.length) {
    console.log('rate-limit-reuse: FAIL');
    fails.forEach((f) => console.log('  - ' + f));
    process.exit(1);
  }
  console.log('rate-limit-reuse: OK');
})().catch((e) => {
  console.log('rate-limit-reuse: FAIL (exception)', e);
  process.exit(1);
});
