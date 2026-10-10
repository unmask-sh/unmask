// The dashboard's 24-hour section: the composition bar, then the tile row
// (requests, what the challenge did, bans); no hourly chart, no AI / crawler
// table (the stats page has both).
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
    tiles: Array.from(document.querySelectorAll('.kpi-grid .kpi')).map(k => k.dataset.kpi),
    // one row at 1400px: every tile's top edge is the same
    oneRow: new Set(Array.from(document.querySelectorAll('.kpi-grid .kpi')).map(k => Math.round(k.getBoundingClientRect().top))).size,
    hourly: !!document.getElementById('hourly-card'),   // gone: the stats page has the series
    comp: !!document.querySelector('#comp-card .comp-body'),
    ai: !!document.querySelector('table.ai-traffic'),
    stages: document.querySelectorAll('.pipe-st, .pipe-side').length,
    // the live parts moved to the realtime page; the day keeps one line of now
    liveLeft: document.querySelectorAll('#live-grid, #geo-card, #recent-card').length,
    nowLine: (function(){ const p = document.querySelector('.now-line'); return p ? { text: p.textContent, link: (p.querySelector('a') || {}).getAttribute ? p.querySelector('a').getAttribute('href') : '' } : null; })(),
    tabLive: !!document.querySelector('.dash-tabs a[href$="/admin/live/"]'),
    navLive: !!document.querySelector('nav.nav a[href$="/admin/live/"]'),
    pageScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    // every tile figure is a number or a dash, never blank
    values: Array.from(document.querySelectorAll('.kpi-grid .kpi .value')).map(v => v.textContent.trim()),
  }));
  ok(shape.day && !shape.hourly && shape.comp, 'the day section or composition card is missing, or the hourly card is back');
  ok(shape.tiles.join(',') === 'requests,serve,pow,captcha,abandon,bans', 'tiles: ' + shape.tiles.join(','));
  ok(shape.oneRow === 1, 'the tiles wrap onto ' + shape.oneRow + ' rows at 1400px');
  ok(!shape.ai, 'the AI / crawler table is still on the dashboard');
  ok(shape.stages === 0, 'the pipeline stages are still on the dashboard');
  ok(shape.liveLeft === 0, 'the live strip, map or recent card is still on the dashboard');
  ok(shape.nowLine && /\/admin\/live\/$/.test(shape.nowLine.link) && /\d/.test(shape.nowLine.text), 'the now line with its link to the realtime page is missing: ' + JSON.stringify(shape.nowLine));
  ok(shape.tabLive && !shape.navLive, 'realtime must be a tab of the dashboard, not a nav entry: ' + JSON.stringify({ tab: shape.tabLive, nav: shape.navLive }));
  ok(!shape.pageScrolls, 'the page scrolls sideways');
  ok(shape.values.every(v => v === '—' || /^[\d,]+$/.test(v)), 'a tile figure is blank: ' + shape.values.join('|'));

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

  // A figure that changed on the redraw flashes; one that did not stays
  // plain.  (The tampered value is what the server's figure differs from.)
  const flash = await page.evaluate(async () => {
    const req = document.querySelector('[data-kpi="requests"] .value');
    const serve = document.querySelector('[data-kpi="serve"] .value');
    if (!req || !serve) return { missing: true };
    req.textContent = 'x';
    await window.unmaskRefreshDay();
    const r2 = document.querySelector('[data-kpi="requests"] .value'), s2 = document.querySelector('[data-kpi="serve"] .value');
    return { changed: r2.classList.contains('v-flash'), same: s2.classList.contains('v-flash'), anim: getComputedStyle(r2).animationName, text: r2.textContent };
  });
  if (flash.missing) {
    ok(false, 'the requests or serve tile is gone');
  } else {
    ok(flash.changed && flash.anim === 'v-flash', 'a changed figure did not flash: ' + JSON.stringify(flash));
    ok(!flash.same, 'an unchanged figure flashed');
    ok(flash.text !== 'x', 'the redraw kept the tampered figure');
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
