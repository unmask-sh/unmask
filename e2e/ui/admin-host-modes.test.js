// The admin-host allowlist uses a host-oriented pattern-mode set (exact /
// subdomain / regex) instead of the generic exact/contains/regex, because a
// substring "contains" on an allowlist admits sub.attacker.com.  This drives a
// real browser to confirm the toggle on that field cycles the host modes and
// never offers contains, while a regex field (bypass-paths) still does and
// an IP list (bypass-ips) has no chip at all.
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

  // A regex field (bypass-paths) uses the generic set incl. contains, and a
  // confirmed row shows the chosen mode as a badge in the list.
  await page.goto(BASE + '/admin/settings/bypass-paths/', { waitUntil: 'networkidle2' });
  const generic = await page.evaluate(async () => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="bp_path"]');
    if (!add) return { err: 'no bypass-paths add button' };
    add.click();
    await new Promise(r => setTimeout(r, 60));
    let input = null;
    document.querySelectorAll('.rule-row.editing .rule-pat-wrap input[name="bp_path"]').forEach(i => { input = i; });
    if (!input) return { err: 'no bp_path input on the new row' };
    const btn = input.parentElement.querySelector('.rule-pat-mode');
    if (!btn) return { err: 'no bypass-paths mode chip' };
    const seen = [btn.dataset.mode];
    for (let i = 0; i < 3; i++) { btn.click(); seen.push(btn.dataset.mode); }
    while (btn.dataset.mode !== 'contains') btn.click();
    input.value = '/feed/';
    const row = input.closest('.rule-row');
    row.querySelector('.rule-save').click();
    await new Promise(r => setTimeout(r, 60));
    const badge = row.querySelector('.rule-view .pat .pat-lit');
    return { seen, badgeMode: badge ? badge.dataset.mode : '', badgeText: badge ? badge.textContent : '', editing: row.classList.contains('editing') };
  });
  ok(!generic.err, 'bypass-paths cycle: ' + (generic.err || ''));
  if (generic.seen) {
    ok(generic.seen.includes('contains'), 'bypass-paths must offer contains, saw: ' + generic.seen.join(','));
    ok(!generic.seen.includes('subdomain'), 'bypass-paths must NOT offer subdomain, saw: ' + generic.seen.join(','));
    ok(generic.editing === false, 'the row confirms');
    ok(generic.badgeMode === 'contains' && generic.badgeText.length > 0, 'the confirmed row shows the mode badge, got ' + JSON.stringify([generic.badgeMode, generic.badgeText]));
  }

  // An IP list is not a pattern: no chip on a new bypass-IP row.
  await page.goto(BASE + '/admin/settings/bypass-ips/', { waitUntil: 'networkidle2' });
  const ipRow = await page.evaluate(async () => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="bypass_ip"]');
    if (!add) return { err: 'no bypass-ips add button' };
    add.click();
    await new Promise(r => setTimeout(r, 60));
    let input = null;
    document.querySelectorAll('.rule-row.editing .rule-pat-wrap input[name="bypass_ip"]').forEach(i => { input = i; });
    if (!input) return { err: 'no bypass_ip input on the new row' };
    return { chip: !!input.parentElement.querySelector('.rule-pat-mode'), chips: document.querySelectorAll('.rule-list[data-rule-name="bypass_ip"] .rule-pat-mode').length };
  });
  ok(!ipRow.err, 'bypass-ips row: ' + (ipRow.err || ''));
  ok(ipRow.chip === false && ipRow.chips === 0, 'an IP list carries no pattern-mode chip, got ' + JSON.stringify(ipRow));

  await browser.close();
  if (fails.length) { console.error('FAIL\n- ' + fails.join('\n- ')); process.exit(1); }
  console.log('admin-host-modes: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
