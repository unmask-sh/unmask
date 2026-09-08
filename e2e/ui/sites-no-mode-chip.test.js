// A defined site is a hostname, not a pattern: the Sites tab's value list must
// not carry the pattern-mode chip that regex fields have.  Between 0.1.25 and
// 0.1.40 it did, a blank row started in "contains" mode, and the submit hook
// prepended "contains:" to the hostname -- which the site normaliser read as
// host:port and stored as the site "contains".  This drives a real browser
// through the exact gesture: add a site row, type a hostname, save, and read
// back what the page shows.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const HOST = 'added-by-ui-e2e.example.com';

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

  await page.goto(BASE + '/admin/settings/sites/', { waitUntil: 'networkidle2' });

  // Existing rows: no chip on any site row (edit lane included).
  const existing = await page.evaluate(() => {
    const list = document.querySelector('.rule-list[data-rule-name="site_defined"]');
    if (!list) return { err: 'no site_defined list' };
    return { rows: list.querySelectorAll('.rule-row').length, chips: list.querySelectorAll('.rule-pat-mode').length };
  });
  ok(!existing.err, 'sites list: ' + (existing.err || ''));
  ok(existing.rows >= 1, 'sites list has stored rows, got ' + existing.rows);
  ok(existing.chips === 0, 'stored site rows must carry no pattern-mode chip, got ' + existing.chips);

  // Add a row the way an operator does, and read the new row's edit lane.
  const added = await page.evaluate(async (host) => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="site_defined"]');
    if (!add) return { err: 'no add button' };
    add.click();
    await new Promise(r => setTimeout(r, 80));
    let input = null;
    document.querySelectorAll('.rule-row.editing input[name="site_defined"]').forEach(i => { input = i; });
    if (!input) return { err: 'no site input on the new row' };
    const chip = input.parentElement.querySelector('.rule-pat-mode');
    input.focus();
    return { chip: !!chip, modeset: input.dataset.modeset || '' };
  }, HOST);
  ok(!added.err, 'add row: ' + (added.err || ''));
  ok(added.chip === false, 'a new site row must not carry the pattern-mode chip');
  ok(added.modeset === '', 'site_defined input must not name a mode set, got ' + JSON.stringify(added.modeset));
  await page.keyboard.type(HOST);

  // Save the tab and read the stored rows back off the reloaded page.
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action*="save?section=sites"] button[type="submit"]'),
  ]);
  const after = await page.evaluate(() => {
    const list = document.querySelector('.rule-list[data-rule-name="site_defined"]');
    if (!list) return { err: 'no site_defined list after save' };
    return {
      pats: Array.from(list.querySelectorAll('.rule-row .rule-view .pat')).map(e => e.textContent.trim()),
      vals: Array.from(list.querySelectorAll('.rule-row input[name="site_defined"]')).map(i => i.value),
      err: (document.querySelector('.flash-err, .rule-err') || {}).textContent || '',
    };
  });
  ok(!after.err || after.pats, 'after save: ' + (after.err || ''));
  if (after.pats) {
    ok(after.pats.some(p => p === HOST), 'saved site must read back as ' + HOST + ', rows: ' + after.pats.join(','));
    ok(!after.pats.includes('contains') && !after.vals.includes('contains'), 'no row may have become "contains", rows: ' + after.pats.join(','));
    ok(!after.vals.some(v => /^(contains|exact|regex):/.test(v)), 'no stored value may carry a mode marker: ' + after.vals.join(','));
  }

  // Put the instance back the way run.sh seeded it (one declared site): drop
  // the row we added and save again.
  const removed = await page.evaluate((host) => {
    const list = document.querySelector('.rule-list[data-rule-name="site_defined"]');
    if (!list) return false;
    let hit = false;
    list.querySelectorAll('.rule-row').forEach(row => {
      const i = row.querySelector('input[name="site_defined"]');
      if (i && i.value === host) { row.remove(); hit = true; }
    });
    return hit;
  }, HOST);
  ok(removed, 'cleanup: the added row must be found for removal');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action*="save?section=sites"] button[type="submit"]'),
  ]);
  const final = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.rule-list[data-rule-name="site_defined"] input[name="site_defined"]')).map(i => i.value));
  ok(!final.some(v => v === HOST), 'cleanup: added site removed again, rows: ' + final.join(','));

  await browser.close();
  if (fails.length) {
    console.error('FAIL sites-no-mode-chip:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok sites-no-mode-chip');
})().catch(e => { console.error('ERROR sites-no-mode-chip: ' + (e.stack || e)); process.exit(1); });
