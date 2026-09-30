// The retention tab's database compaction card.
//
// A compaction holds the daemon's writes for as long as it runs, so the card
// has to say, before anyone presses anything, what a run gives back and what
// it needs: the disk for the copy and its write-back, how long, and the
// events the daemon keeps in memory meanwhile.  The button is only live when
// the run is worth it and allowed; otherwise it says why not.  The throwaway
// instance's database is small, so here that reason is "little to give back".
//
// The flow itself -- the run, the hold, the notice, the write-back -- is
// exercised by the handler tests and the docker scenario 64.
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
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(e.message));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/settings/retention/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `retention tab status ${resp.status()}`);

  const res = await page.evaluate(() => {
    const card = document.getElementById('vacuum-card');
    if (!card) return { missing: true };
    const rows = {};
    card.querySelectorAll('[data-vacuum]').forEach(el => { rows[el.getAttribute('data-vacuum')] = el.textContent.trim(); });
    const btn = document.getElementById('vacuum-run');
    const blocked = document.getElementById('vacuum-blocked');
    const r = card.getBoundingClientRect();
    return {
      rows,
      btnDisabled: btn ? btn.disabled : null,
      blocked: blocked ? blocked.textContent.trim() : '',
      overflow: card.scrollWidth - card.clientWidth,
      width: r.width,
      // The card sits in the retention form: the button must not submit it.
      btnType: btn ? btn.getAttribute('type') : '',
    };
  });

  if (res.missing) {
    ok(false, 'no compaction card on the retention tab (SQLite install)');
  } else {
    for (const k of ['size', 'disk', 'time', 'held']) {
      ok(res.rows[k] && /\d/.test(res.rows[k]), `the card's ${k} line carries no figure: ${JSON.stringify(res.rows[k])}`);
    }
    ok(res.btnType === 'button', `the compaction button is a ${res.btnType}; it would submit the retention form`);
    ok(res.btnDisabled === true, 'the button is live on a database with little to give back');
    ok(res.blocked.length > 10, `a disabled button with no reason next to it: ${JSON.stringify(res.blocked)}`);
    ok(res.overflow <= 1, `the card scrolls sideways by ${res.overflow}px at 1280px`);
  }
  ok(jsErrors.length === 0, 'page errors: ' + jsErrors.join(' | '));

  // No compaction has run: no notice anywhere.
  await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  const notice = await page.evaluate(() => {
    const el = document.getElementById('vacup');
    return el ? getComputedStyle(el).display : 'absent';
  });
  ok(notice === 'absent' || notice === 'none', `a compaction notice with no run: ${notice}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('vacuum-card: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
