// The admin-host allowlist uses a host-oriented pattern-mode set (exact /
// subdomain / regex) instead of the generic exact/contains/regex, because a
// substring "contains" on an allowlist admits sub.attacker.com.  This drives a
// real browser to confirm the toggle on that field cycles the host modes and
// never offers contains, while a normal field (bypass-ips) still does.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
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
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  await page.goto(BASE + '/admin/settings/network/', { waitUntil: 'networkidle2' });

  // Add a fresh admin-host row, confirm it carries the host mode set, and read
  // the mode chip through a full cycle.  (A field with no stored rows only has
  // its input inside a <template>, which querySelector cannot see, so we add a
  // row first.)
  const cycle = await page.evaluate(async () => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="admin_allowed_hosts"]');
    if (!add) return { err: 'no add button' };
    add.click();
    await new Promise(r => setTimeout(r, 80));
    let input = null;
    document.querySelectorAll('.rule-row.editing .rule-pat-wrap input[name="admin_allowed_hosts"]').forEach(i => { input = i; });
    if (!input) return { err: 'no admin-host input on new row' };
    const btn = input.parentElement.querySelector('.rule-pat-mode');
    if (!btn) return { err: 'no mode chip on new row' };
    const modeset = input.dataset.modeset || '';
    const seen = [btn.dataset.mode];
    for (let i = 0; i < 3; i++) { btn.click(); seen.push(btn.dataset.mode); }
    return { seen, modeset };
  });
  ok(!cycle.err, 'admin-host cycle: ' + (cycle.err || ''));
  ok(cycle.modeset === 'host', 'admin_allowed_hosts input data-modeset = ' + JSON.stringify(cycle.modeset) + ', want "host"');
  if (cycle.seen) {
    ok(!cycle.seen.includes('contains'), 'admin-host must NOT offer contains, saw: ' + cycle.seen.join(','));
    ok(cycle.seen.includes('subdomain'), 'admin-host must offer subdomain, saw: ' + cycle.seen.join(','));
    ok(cycle.seen.includes('exact') && cycle.seen.includes('regex'), 'admin-host must keep exact+regex, saw: ' + cycle.seen.join(','));
  }

  // A normal field (bypass-ips) still uses the generic set incl. contains.
  await page.goto(BASE + '/admin/settings/bypass-ips/', { waitUntil: 'networkidle2' });
  const generic = await page.evaluate(async () => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="bypass_ip"]');
    if (!add) return { err: 'no bypass add button' };
    add.click();
    await new Promise(r => setTimeout(r, 60));
    let btn = null;
    document.querySelectorAll('.rule-row.editing .rule-pat-wrap input[name="bypass_ip"]').forEach(i => {
      btn = i.parentElement.querySelector('.rule-pat-mode');
    });
    if (!btn) return { err: 'no bypass mode chip' };
    const seen = [btn.dataset.mode];
    for (let i = 0; i < 3; i++) { btn.click(); seen.push(btn.dataset.mode); }
    return { seen };
  });
  ok(!generic.err, 'bypass cycle: ' + (generic.err || ''));
  if (generic.seen) {
    ok(generic.seen.includes('contains'), 'bypass-ips must still offer contains, saw: ' + generic.seen.join(','));
    ok(!generic.seen.includes('subdomain'), 'bypass-ips must NOT offer subdomain, saw: ' + generic.seen.join(','));
  }

  await browser.close();
  if (fails.length) { console.error('FAIL\n- ' + fails.join('\n- ')); process.exit(1); }
  console.log('admin-host-modes: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
