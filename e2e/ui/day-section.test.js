// The dashboard's 24-hour section: the pipeline card (five stages above the
// composition bar), the hourly today/yesterday chart, no AI / crawler table.
// The section is redrawn from the server every minute; after a redraw the
// composition's segment toggles must still work, since their script binds to
// the card that was replaced.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_SHOT_DIR.
const puppeteer = require('puppeteer-core');
const path = require('path');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
  const resp = await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ status ${resp.status()}`);

  const shape = await page.evaluate(() => ({
    day: !!document.getElementById('day-section'),
    stages: Array.from(document.querySelectorAll('.pipe-st')).map(s => s.dataset.stage),
    hourly: !!document.getElementById('hourly-card'),
    comp: !!document.querySelector('#comp-card .comp-body'),
    ai: !!document.querySelector('table.ai-traffic'),
    kpiGrid: !!document.querySelector('.kpi-grid'),
    sideTiles: document.querySelectorAll('.pipe-side .kpi').length,
    pageScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    // every stage figure is a number or a dash, never blank
    values: Array.from(document.querySelectorAll('.pipe-v')).map(v => v.textContent.trim()),
  }));
  ok(shape.day && shape.hourly && shape.comp, 'the day section, hourly card or composition card is missing');
  ok(shape.stages.join(',') === 'requests,bypass,rl,serve,pass', 'stages: ' + shape.stages.join(','));
  ok(!shape.ai, 'the AI / crawler table is still on the dashboard');
  ok(!shape.kpiGrid, 'the old KPI grid is still on the dashboard');
  ok(shape.sideTiles === 2, `${shape.sideTiles} side tiles, want 2 (abandon, bans)`);
  ok(!shape.pageScrolls, 'the page scrolls sideways');
  ok(shape.values.every(v => v === '—' || /^[\d,]+$/.test(v)), 'a stage figure is blank: ' + shape.values.join('|'));

  // Toggle a composition segment, redraw the section, toggle again.
  const comp = await page.evaluate(async () => {
    const chip = document.querySelector('#comp-card .comp-chip a.comp-tgl[href]');
    if (!chip) return { skipped: true };
    const key = chip.closest('.comp-chip').dataset.key;
    chip.click();
    const offBefore = document.querySelector('#comp-card .comp-chip[data-key="' + key + '"]').classList.contains('comp-out');
    await window.unmaskRefreshDay();
    const stillOff = document.querySelector('#comp-card .comp-chip[data-key="' + key + '"]').classList.contains('comp-out');
    const again = document.querySelector('#comp-card .comp-chip[data-key="' + key + '"] a.comp-tgl');
    again.click();
    const backOn = !document.querySelector('#comp-card .comp-chip[data-key="' + key + '"]').classList.contains('comp-out');
    return { key, offBefore, stillOff, backOn, dayErr: document.getElementById('day-err').hidden };
  });
  if (!comp.skipped) {
    ok(comp.offBefore, 'the first toggle did not exclude the segment');
    ok(comp.stillOff, 'the redraw lost the excluded segment (the server did not get the state)');
    ok(comp.backOn, 'the toggle no longer works after the redraw (the script was not rebound)');
    ok(comp.dayErr === true, 'the day refresh reported a failure');
  }

  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'overview-full.png'), fullPage: true }); } catch (e) {}
  }
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('day-section: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
