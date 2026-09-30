// The retention tab's database compaction card.
//
// A compaction holds the daemon's writes for as long as it runs, so the card
// has to say, before anyone presses anything, what a run gives back and what
// it needs: the disk for the copy and its write-back, how long, and the
// events the daemon keeps in memory meanwhile.  The button is only live when
// the run is worth it and allowed; otherwise it says why not.  The throwaway
// instance's database is small, so here that reason is "little to give back".
//
// The flow itself -- the run, the hold, its progress on this card and the
// top bar's sign of it elsewhere, the write-back -- is exercised by the
// handler tests and the docker scenario 64.
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
      progress: !!document.getElementById('vacuum-progress'),
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
    for (const k of ['size', 'disk', 'time', 'held', 'mem']) {
      ok(res.rows[k] && /\d/.test(res.rows[k]), `the card's ${k} line carries no figure: ${JSON.stringify(res.rows[k])}`);
    }
    ok(!res.progress, 'the card shows a run in progress with none going');
    ok(res.btnType === 'button', `the compaction button is a ${res.btnType}; it would submit the retention form`);
    ok(res.btnDisabled === true, 'the button is live on a database with little to give back');
    ok(res.blocked.length > 10, `a disabled button with no reason next to it: ${JSON.stringify(res.blocked)}`);
    ok(res.overflow <= 1, `the card scrolls sideways by ${res.overflow}px at 1280px`);

    // The button asks in a modal of the card's own, never the browser's
    // confirm().  The database here has too little to give back, so the
    // button is made live for the test: the modal opens with the focus on
    // backing out, backing out (or Esc) closes it, and nothing is sent.
    const posts = [];
    page.on('request', r => { if (r.method() === 'POST' && r.url().includes('/admin/api/vacuum')) posts.push(r.url()); });
    page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });
    await page.evaluate(() => { const b = document.getElementById('vacuum-run'); b.disabled = false; b.removeAttribute('style'); });
    const modalState = () => page.evaluate(() => {
      const d = document.getElementById('vacuum-dialog');
      if (!d) return { missing: true };
      const r = d.getBoundingClientRect();
      const a = document.activeElement;
      return {
        open: d.open, modal: d.matches(':modal'), top: r.top, bottom: r.bottom, vh: innerHeight,
        notes: d.querySelectorAll('li').length, overflow: d.scrollWidth - d.clientWidth,
        backFocused: !!(a && a.hasAttribute('data-back') && d.contains(a)),
        types: [...d.querySelectorAll('button')].map(b => b.getAttribute('type')),
      };
    });
    await page.click('#vacuum-run');
    let m = await modalState();
    if (m.missing) {
      ok(false, 'no start modal in the card');
    } else {
      ok(m.open && m.modal, 'the compaction button did not open its modal');
      ok(m.notes === 4, `the modal lists ${m.notes} points about the run, want 4`);
      ok(m.backFocused, 'the modal opened without the focus on backing out');
      ok(m.top >= 0 && m.bottom <= m.vh, `the modal is off screen (${m.top}-${m.bottom} of ${m.vh})`);
      ok(m.overflow <= 1, `the modal scrolls sideways by ${m.overflow}px`);
      ok(m.types.every(t => t === 'button'), `a modal button would submit the retention form: ${m.types}`);
      await page.click('#vacuum-dialog [data-back]');
      m = await modalState();
      ok(!m.open, 'backing out did not close the modal');
      await page.click('#vacuum-run');
      await page.keyboard.press('Escape');
      m = await modalState();
      ok(!m.open, 'Esc did not close the modal');
      ok(posts.length === 0, `backing out sent ${posts.join(', ')}`);
    }
  }
  ok(jsErrors.length === 0, 'page errors: ' + jsErrors.join(' | '));

  // No compaction has run: no sign of one in the top bar.
  await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  const notice = await page.evaluate(() => {
    const el = document.getElementById('vacpill');
    return el ? getComputedStyle(el).display : 'absent';
  });
  ok(notice === 'absent' || notice === 'none', `a compaction sign with no run: ${notice}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('vacuum-card: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
