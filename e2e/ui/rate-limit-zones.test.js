// Browser-level check of the rate-limit tab since forward-auth was frozen.
// Against a real running admin (real templates + the zone-row JS), verifies:
//   - the window column is gone from both tables (only forward-auth counted
//     with it; the nginx module counts per minute), and the header, a new
//     row and its warning row agree on the zones table's column count,
//   - a zone added from the template and confirmed renders its values in view
//     mode (the row JS runs without a page error),
//   - saving keeps the zone, and the saved banner speaks of the nginx reload
//     and the gateway container -- not of forward-auth,
//   - the zone can be removed again (the test leaves the config as it found it).
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

const ZONE = 'uizone';

async function save(page) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action*="section=rate_limit"] button[type="submit"]'),
  ]);
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

  // ---- login ----
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // ---- the tab's shape ----
  const resp = await page.goto(BASE + '/admin/settings/rate-limit/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/rate-limit/ status ${resp.status()}`);
  const shape = await page.evaluate(() => {
    const tpl = document.getElementById('rl-zone-row-tpl');
    const tplRow = tpl && tpl.content.querySelector('tr.zone-row');
    const tplWarn = tpl && tpl.content.querySelector('tr.zone-warn-row td');
    return {
      windowInputs: document.querySelectorAll('[name$="_window"]').length,
      zvWindow: document.querySelectorAll('.zv-window').length,
      axisCols: document.querySelectorAll('#axis-table thead th').length,
      zoneCols: document.querySelectorAll('#zones-table thead th').length,
      tplCells: tplRow ? tplRow.children.length : -1,
      warnSpan: tplWarn ? Number(tplWarn.getAttribute('colspan')) : -1,
    };
  });
  ok(shape.windowInputs === 0, `${shape.windowInputs} window input(s) still on the tab`);
  ok(shape.zvWindow === 0, `${shape.zvWindow} window cell(s) still in the zones table`);
  ok(shape.axisCols === 4, `axis table has ${shape.axisCols} columns, want 4 (axis / r/min / burst / mode)`);
  ok(shape.zoneCols === shape.tplCells, `zones header has ${shape.zoneCols} columns, a new row ${shape.tplCells} cells`);
  ok(shape.warnSpan === shape.zoneCols, `a zone's warning row spans ${shape.warnSpan} of ${shape.zoneCols} columns`);

  // ---- add a zone, confirm it ----
  await page.evaluate(() => window.rlAddZone());
  const view = await page.evaluate((name) => {
    const rows = document.querySelectorAll('#zones-tbody tr.zone-row');
    const tr = rows[rows.length - 1];
    const set = (sfx, v) => { const el = tr.querySelector('[name$="_' + sfx + '"]'); el.value = v; };
    set('name', name);
    set('paths', '^/ui-zone/');
    set('rpm', '7');
    set('burst', '2');
    tr.querySelector('.z-ok').click();
    const text = (sel) => (tr.querySelector(sel) || {}).textContent || '';
    return {
      editing: tr.classList.contains('editing'),
      name: text('.zv-name'), rpm: text('.zv-rpm'), burst: text('.zv-burst'),
    };
  }, ZONE);
  ok(!view.editing, 'the confirmed zone row is still in edit mode');
  ok(view.name === ZONE && view.rpm === '7' && view.burst === '2',
    `the confirmed row shows name=${view.name} rpm=${view.rpm} burst=${view.burst}`);

  // ---- save: the zone stays, the banner is the module's ----
  await save(page);
  const after = await page.evaluate(() => ({
    banner: (document.querySelector('.banner.ok') || {}).textContent || '',
    names: Array.from(document.querySelectorAll('#zones-tbody .zv-name')).map((e) => e.textContent),
  }));
  ok(after.names.includes(ZONE), `after the save the zones are [${after.names.join(', ')}]`);
  ok(after.banner.includes('nginx -s reload') && after.banner.includes('gateway') && !/forward-auth/i.test(after.banner),
    `saved banner: ${after.banner.trim()}`);

  // ---- remove it again ----
  await page.evaluate((name) => {
    const tr = Array.from(document.querySelectorAll('#zones-tbody tr.zone-row'))
      .find((r) => (r.querySelector('.zv-name') || {}).textContent === name);
    if (tr) tr.querySelector('.z-del').click();
  }, ZONE);
  await save(page);
  const left = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#zones-tbody .zv-name')).map((e) => e.textContent));
  ok(!left.includes(ZONE), `the zone could not be removed: [${left.join(', ')}]`);

  ok(errors.length === 0, `page error(s): ${errors.join(' | ')}`);
  await browser.close();
  if (fails.length) {
    console.log('rate-limit-zones: FAIL');
    fails.forEach((f) => console.log('  - ' + f));
    process.exit(1);
  }
  console.log('rate-limit-zones: OK');
})().catch((e) => {
  console.log('rate-limit-zones: FAIL (exception)', e);
  process.exit(1);
});
