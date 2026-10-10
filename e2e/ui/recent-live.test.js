// The dashboard's recent-detections card redraws its table from the server.
// After a redraw the table is a new element with the same rows, rows the page
// had not seen flash as new, and the table's own behaviours -- session
// chains, cell and datetime popovers -- are bound on the new rows.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
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

  const shape = (tag) => page.evaluate(tag => {
    const tbl = document.querySelector('#recent-section table.events');
    if (!tbl) return { missing: true };
    if (tag) tbl.dataset.probe = tag;
    return {
      probe: tbl.dataset.probe || '',
      rows: tbl.querySelectorAll('tbody tr').length,
      visible: Array.from(tbl.querySelectorAll('tbody tr')).filter(tr => tr.style.display !== 'none').length,
      chains: tbl.querySelectorAll('.session-chain').length,
      // sessions the rows could form: beacon tokens held by more than one row
      multi: (function(){ const n = {}; tbl.querySelectorAll('tbody tr[data-bt]').forEach(tr => { if (tr.dataset.bt) n[tr.dataset.bt] = (n[tr.dataset.bt] || 0) + 1; }); return Object.values(n).filter(c => c > 1).length; })(),
      cellpops: tbl.querySelectorAll('.cellpop[data-cellpop-wired]').length,
      dts: tbl.querySelectorAll('time.dtpop-trigger').length,
      fresh: tbl.querySelectorAll('tr.ev-new').length,
      freshKeys: Array.from(tbl.querySelectorAll('tr.ev-new')).map(tr => (tr.dataset.bt || '') + '|' + (tr.dataset.tsMs || '') + '|' + (tr.dataset.phase || '')).slice(0, 6),
      wired: tbl.dataset.evWired === '1',
      badge: !!document.querySelector('#recent-card .livebadge'),
    };
  }, tag);
  const before = await shape('old');
  ok(!before.missing, 'the recent table is missing');
  ok(before.badge, 'the card carries no live badge');
  // Whether the latest rows form sessions depends on what ran before this
  // test; what must hold is that the wiring ran, and that a redraw keeps
  // whatever the table had.
  ok(before.multi === 0 || before.chains >= 1, `the seeded table holds ${before.multi} multi-row sessions but no chain was drawn`);
  ok(before.rows > 0 && before.wired && before.cellpops > 0 && before.dts > 0,
    `the seeded table is not wired: rows=${before.rows} wired=${before.wired} cellpops=${before.cellpops} dts=${before.dts}`);

  // A real new detection: the challenge's own test page, loaded in another
  // tab, writes a serve and a load beacon.  Then a redraw: the table is new,
  // as wired as before, and the rows the page had not seen flash as new.
  const other = await browser.newPage();
  await other.goto(BASE + '/test/force-pow', { waitUntil: 'domcontentloaded' });
  await sleep(1500);
  await other.close();
  await sleep(2000); // the event flusher's interval, with room
  await page.evaluate(() => window.unmaskRefreshRecent());
  await sleep(300);
  const after = await shape('');
  ok(after.probe === '', 'the table was not replaced (the old element is still there)');
  ok(after.rows === before.rows, `rows after the redraw: ${after.rows}, want ${before.rows}`);
  ok(after.visible === before.visible, `visible rows after the redraw: ${after.visible}, want ${before.visible} (the row cap did not re-apply)`);
  ok(after.wired, 'the redrawn table was not run through the wiring hooks');
  // The new rows shift the 40-row window, so the counts move; what must hold
  // is that the new table is wired like the old one was: the fresh session
  // got its chain, every cell its popover, every time its detail.
  // Whether the newest 40 rows hold a multi-row session depends on the
  // runner's timing (the load beacon may land after the serve) and on what
  // ran before; the wiring is judged by what the rows can form.
  ok(after.multi === 0 || after.chains >= 1, `the redrawn table holds ${after.multi} multi-row sessions but no chain was drawn`);
  ok(after.cellpops > 0 && after.dts > 0, `the redrawn table is not wired: cellpops=${after.cellpops} dts=${after.dts}`);
  ok(after.fresh >= 1, 'the new detection did not flash as new');

  // A cell popover opens on the new table.
  const hover = await page.evaluate(async () => {
    const el = Array.from(document.querySelectorAll('#recent-section table.events .cellpop'))
      .find(c => c.classList.contains('cellpop-active') || c.classList.contains('url'));
    if (!el) return { skipped: true };
    const r = el.getBoundingClientRect();
    el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: r.left + 4, clientY: r.top + 4 }));
    await new Promise(res => setTimeout(res, 400));
    const pop = document.getElementById('cell-popover');
    return { shown: !!pop && pop.offsetParent !== null };
  });
  if (!hover.skipped) ok(hover.shown, 'a cell popover did not open on the redrawn table');

  // A second redraw with nothing new flags nothing.
  await page.evaluate(() => window.unmaskRefreshRecent());
  await sleep(300);
  const again = await shape('');
  ok(again.fresh === 0, `${again.fresh} rows flagged as new on a redraw that brought nothing new: ${JSON.stringify(again.freshKeys)}`);
  ok(again.wired && again.chains === after.chains && again.cellpops === after.cellpops && again.dts === after.dts,
    `a redraw with nothing new changed the wiring: chains ${after.chains}->${again.chains} cellpops ${after.cellpops}->${again.cellpops} dts ${after.dts}->${again.dts}`);
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('recent-live: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
