// The bypass-paths tab: a custom row carries a methods picker -- every method,
// or GET / HEAD / OPTIONS only.  Driven through a real browser, because the
// row's controls are submitted as parallel columns and its folded view is
// rebuilt by the page's own script:
//   - a new row ships on "every method", the way a row read before the
//     picker existed;
//   - confirming a row set to GET / HEAD / OPTIONS only puts the methods on
//     the folded row, in the picker's words, and a row left on every method
//     shows nothing;
//   - save and reload: each row comes back with the value it was saved with,
//     with a row of the other kind between them (the columns stay aligned);
//   - turning the picker back takes the mark off, and that is saved too.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const LIST = 'bp_path';
const FEED = '^/ui-e2e-methods-feed/';
const HOOKS = '^/ui-e2e-methods-hooks/';
const RSS = '^/ui-e2e-methods-rss$';
const SAVE = 'form[action*="save?section=bypass-paths"] button[type="submit"]';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// The rows this spec added, as the page shows them: the picker's value, the
// folded row's methods pill (null when there is none) and the site.
const readRows = (page) => page.evaluate((name) => {
  const out = {};
  document.querySelectorAll('.rule-list[data-rule-name="' + name + '"] .rule-row').forEach(row => {
    const input = row.querySelector('input[name="' + name + '"]');
    if (!input || input.value.indexOf('ui-e2e-methods') < 0) return;
    const sel = row.querySelector('select[name="bp_methods"]');
    const pill = row.querySelector('.rule-view [data-pill="methods"]');
    const site = row.querySelector('input[name="bp_site"]');
    out[input.value] = {
      methods: sel ? sel.value : null,
      pill: pill ? pill.textContent.trim() : null,
      site: site ? site.value : null,
      editing: row.classList.contains('editing'),
    };
  });
  return out;
}, LIST);

// Add a row the way an operator does: the button, the pattern, the picker,
// then the row's own confirm.
const addRow = (page, pat, methods, site) => page.evaluate(async (name, pat, methods, site) => {
  const add = document.querySelector('.rule-add-bottom[data-target-list="' + name + '"]');
  if (!add) return { err: 'no add button' };
  add.click();
  await new Promise(res => setTimeout(res, 80));
  const rows = document.querySelectorAll('.rule-list[data-rule-name="' + name + '"] .rule-row.editing');
  const row = rows[rows.length - 1];
  if (!row) return { err: 'no new row' };
  const sel = row.querySelector('select[name="bp_methods"]');
  if (!sel) return { err: 'the new row has no methods picker' };
  const shipped = sel.value;
  const opts = Array.from(sel.options).map(o => o.value);
  const input = row.querySelector('input[name="' + name + '"]');
  input.value = pat;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  if (site) row.querySelector('input[name="bp_site"]').value = site;
  sel.value = methods;
  sel.dispatchEvent(new Event('change', { bubbles: true }));
  const label = sel.options[sel.selectedIndex].textContent.trim();
  row.querySelector('.rule-save').click();
  const pill = row.querySelector('.rule-view [data-pill="methods"]');
  return { shipped, opts, label, pill: pill ? pill.textContent.trim() : null, folded: !row.classList.contains('editing') };
}, LIST, pat, methods, site || '');

const save = (page) => Promise.all([
  page.waitForNavigation({ waitUntil: 'networkidle2' }),
  page.click(SAVE),
]);

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

  const resp = await page.goto(BASE + '/admin/settings/bypass-paths/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, 'bypass-paths tab status ' + resp.status());

  // 1. New rows: one restricted, one not, one restricted for a single site.
  const feed = await addRow(page, FEED, 'safe');
  ok(!feed.err, 'add row: ' + (feed.err || ''));
  ok(feed.shipped === '', 'a new row must ship on every method, got ' + JSON.stringify(feed.shipped));
  ok(JSON.stringify(feed.opts) === JSON.stringify(['', 'safe']), 'picker options unexpected: ' + JSON.stringify(feed.opts));
  ok(feed.folded, 'confirming the row must fold it');
  ok(feed.pill !== null && feed.pill === feed.label,
    'the folded row must name the methods in the picker\'s words: pill ' + JSON.stringify(feed.pill) + ', option ' + JSON.stringify(feed.label));
  const hooks = await addRow(page, HOOKS, '');
  ok(!hooks.err && hooks.pill === null, 'a row on every method must carry no methods pill: ' + JSON.stringify(hooks));
  const rss = await addRow(page, RSS, 'safe', 'shop.example.com');
  ok(!rss.err && rss.pill !== null, 'the per-site restricted row must carry the pill: ' + JSON.stringify(rss));

  // 2. Save and read back.
  await save(page);
  let rows = await readRows(page);
  ok(rows[FEED] && rows[FEED].methods === 'safe' && rows[FEED].pill !== null && !rows[FEED].editing,
    'after save the restricted row must come back restricted and folded: ' + JSON.stringify(rows[FEED]));
  ok(rows[HOOKS] && rows[HOOKS].methods === '' && rows[HOOKS].pill === null,
    'after save the every-method row must come back unrestricted: ' + JSON.stringify(rows[HOOKS]));
  ok(rows[RSS] && rows[RSS].methods === 'safe' && rows[RSS].pill !== null && rows[RSS].site === 'shop.example.com',
    'after save the per-site row must keep its site and its restriction: ' + JSON.stringify(rows[RSS]));

  // 3. The picker is hidden on a folded row and shown on an open one.
  const vis = await page.evaluate((name, pat) => {
    let row = null;
    document.querySelectorAll('.rule-list[data-rule-name="' + name + '"] .rule-row').forEach(r => {
      const i = r.querySelector('input[name="' + name + '"]');
      if (i && i.value === pat) row = r;
    });
    if (!row) return null;
    const sel = row.querySelector('select[name="bp_methods"]');
    const folded = getComputedStyle(sel).display;
    row.querySelector('.rule-edit').click();
    const open = getComputedStyle(sel).display;
    // Turn the restriction off and confirm: the pill goes.
    sel.value = '';
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    row.querySelector('.rule-save').click();
    return { folded, open, pill: !!row.querySelector('.rule-view [data-pill="methods"]') };
  }, LIST, FEED);
  ok(vis && vis.folded === 'none' && vis.open !== 'none', 'the picker shows only while the row is open: ' + JSON.stringify(vis));
  ok(vis && !vis.pill, 'turning the picker back to every method must take the pill off the folded row');

  await save(page);
  rows = await readRows(page);
  ok(rows[FEED] && rows[FEED].methods === '' && rows[FEED].pill === null,
    'the row turned back must be saved as every method: ' + JSON.stringify(rows[FEED]));
  ok(rows[RSS] && rows[RSS].methods === 'safe', 'the other restricted row must be untouched: ' + JSON.stringify(rows[RSS]));

  // Put the instance back the way run.sh seeded it: drop our rows and save.
  const removed = await page.evaluate((name) => {
    let n = 0;
    document.querySelectorAll('.rule-list[data-rule-name="' + name + '"] .rule-row').forEach(row => {
      const i = row.querySelector('input[name="' + name + '"]');
      if (i && i.value.indexOf('ui-e2e-methods') >= 0) { row.remove(); n++; }
    });
    return n;
  }, LIST);
  ok(removed === 3, 'cleanup: three added rows must be found for removal, found ' + removed);
  await save(page);
  rows = await readRows(page);
  ok(Object.keys(rows).length === 0, 'cleanup: rows left behind: ' + JSON.stringify(rows));

  await browser.close();
  if (fails.length) {
    console.error('FAIL bypass-row-methods:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok bypass-row-methods');
})().catch(e => { console.error('ERROR bypass-row-methods: ' + (e.stack || e)); process.exit(1); });
