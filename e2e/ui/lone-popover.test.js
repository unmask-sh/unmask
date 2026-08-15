// A row with no chain gets its own small popover, and its timestamp must be a
// timestamp.
//
// The builder read the whole date cell with textContent.  That cell also holds
// the Host and site badges, so the popover printed "2026/08/15 13:50:01
// ko.tool.uic.jp" -- the host glued onto the time, unlabelled, reading as part
// of it.  And redundantly: the badge is displayed in the row itself, in the
// very cell the popover was opened next to.
//
// run.sh seeds a lone serve for an undeclared Host, which is exactly this
// shape: no chain, and a badge sharing the date cell.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
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

  const res = await page.evaluate(async () => {
    // A visible row with no chain whose date cell also carries a badge.
    const tr = Array.from(document.querySelectorAll('table.events tbody tr')).find(r => {
      if (r.style.display === 'none') return false;
      const cell = r.querySelector('td:nth-child(5)');
      const at = r.querySelector('td:first-child');
      return cell && at && !cell.querySelector('.session-chain') &&
             at.querySelector('.host-badge, .site-badge') && cell.querySelector('.phase-pill');
    });
    if (!tr) return { missing: true };
    const at = tr.querySelector('td:first-child');
    const badge = at.querySelector('.host-badge, .site-badge').textContent.trim();
    const pill = tr.querySelector('td:nth-child(5) .phase-pill');
    pill.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    await new Promise(r => setTimeout(r, 400));
    const lines = document.querySelectorAll('.session-timeline .ts-mono');
    const shown = lines.length ? lines[lines.length - 1].textContent.trim() : null;
    return {
      badge,
      shown,
      rowTime: (at.querySelector('time') || {}).textContent.trim(),
    };
  });

  if (res.missing) {
    ok(false, 'no chainless row with a badge in its date cell -- run.sh seeding changed');
  } else {
    ok(res.shown != null, 'the lone row opened no popover');
    // The point: the badge must not have come along for the ride.
    ok(res.shown && res.shown.indexOf(res.badge) < 0,
      `the popover repeats the host/site already shown in the row: ${JSON.stringify(res.shown)}`);
    // And it still shows the time it is supposed to show.
    ok(res.shown === res.rowTime,
      `the popover's timestamp does not match the row's: ${JSON.stringify(res.shown)} vs ${JSON.stringify(res.rowTime)}`);
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('lone-popover: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
