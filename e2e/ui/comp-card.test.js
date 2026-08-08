// Browser-level checks for the overview page's traffic-composition card.
//
// Server-side tests pin the arithmetic contract; what they cannot see is the
// page as a browser runs it -- the click path that mirrors that arithmetic in
// JS, CSS specificity fights between the legend and its popovers, and layout
// shift.  Each of those has already broken once:
//
//   - the segment-toggle script recomputes shares client-side (drift risk
//     against Go's pctLabel),
//   - the breakdown popover's row rules lost a specificity fight with
//     ".comp-legend span" in one home (in-place) while staying green in the
//     other (the pinned body-level clone),
//   - toggling used to reflow every chip in the legend.
//
// Driven by run.sh, which boots a throwaway admin with seeded counters.
// Environment: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_OUT.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const OUT = process.env.UI_E2E_OUT || '.';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

// Mirror of Go's pctLabel, including the "<0.1%" floor -- the whole point is
// that the two implementations cannot be allowed to disagree.
function pctLabel(n, t) {
  if (t <= 0 || n <= 0) return '0%';
  const p = (n / t) * 100;
  if (p < 0.05) return '<0.1%';
  return p.toFixed(1) + '%';
}

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  await page.goto(BASE + '/admin/?comp=all', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#comp-card .comp-chip', { timeout: 8000 });

  const read = () => page.evaluate(() => {
    const card = document.getElementById('comp-card');
    const chips = {};
    card.querySelectorAll('.comp-chip').forEach(c => {
      const a = c.querySelector('a.comp-tgl');
      chips[c.dataset.key] = {
        count: parseInt(c.dataset.count, 10),
        nonhuman: c.dataset.nonhuman === 'true',
        out: c.classList.contains('comp-out'),
        share: (c.querySelector('.comp-share') || {}).textContent || '',
        isLink: !!(a && a.getAttribute('href')),
      };
    });
    return {
      chips,
      total: parseInt(card.querySelector('.comp-view').dataset.total, 10),
      pct: card.querySelector('.comp-pct').textContent.trim(),
      caption: card.querySelector('.comp-of').textContent.trim(),
      state: card.querySelector('.comp-body').dataset.state,
      barShown: Array.from(card.querySelectorAll('.comp-seg'))
        .filter(s => s.style.display !== 'none').map(s => s.dataset.key),
      cookie: document.cookie,
    };
  });

  // Every displayed figure must match the arithmetic recomputed from the
  // counts the page itself advertises.
  const verify = (v, label) => {
    const on = Object.keys(v.chips).filter(k => !v.chips[k].out);
    let denom = v.total;
    let nonhuman = 0;
    for (const [, c] of Object.entries(v.chips)) {
      if (c.out) denom -= c.count; else if (c.nonhuman) nonhuman += c.count;
    }
    const wantPct = denom > 0 ? ((nonhuman / denom) * 100).toFixed(1) : '0.0';
    ok(v.pct.startsWith(wantPct), `${label}: headline ${v.pct} != ${wantPct}%`);
    ok(v.caption.replace(/[^0-9]/g, '').includes(String(denom)),
      `${label}: caption "${v.caption}" does not name denom ${denom}`);
    for (const [k, c] of Object.entries(v.chips)) {
      if (c.out) ok(!/%/.test(c.share), `${label}: excluded ${k} still shows a share "${c.share}"`);
      else ok(c.share === pctLabel(c.count, denom), `${label}: ${k} share "${c.share}" != ${pctLabel(c.count, denom)}`);
    }
    ok(v.barShown.sort().join() === on.sort().join(), `${label}: bar shows [${v.barShown}] want [${on}]`);
  };

  // ---- 1. toggle contract ------------------------------------------------
  let v = await read();
  ok(v.state === 'all', `initial state ${v.state} != all`);
  verify(v, 'all');

  await page.click('.comp-chip[data-key="bypass"] a.comp-tgl');
  v = await read();
  ok(v.state === 'judged', `after bypass off: state ${v.state} != judged`);
  verify(v, 'judged');
  ok(v.cookie.includes('unmask_comp_seg=judged'), 'cookie does not carry judged');

  await page.click('.comp-chip[data-key="human"] a.comp-tgl');
  await page.click('.comp-chip[data-key="other"] a.comp-tgl');
  v = await read();
  ok(v.state === 'benign-bad', `bots-only state ${v.state} != benign-bad`);
  verify(v, 'bots-only');
  ok(v.pct.startsWith('100.0'), `bots-only headline ${v.pct} != 100.0%`);

  // The last enabled segment must pin (an anchor without href), on the JS
  // path exactly as the server renders it.
  await page.click('.comp-chip[data-key="benign"] a.comp-tgl');
  v = await read();
  ok(v.state === 'bad', `solo state ${v.state} != bad`);
  ok(!v.chips.bad.isLink, 'last enabled chip is still a link');

  // Reload: the cookie must bring the same state back, server-rendered.
  await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  v = await read();
  ok(v.state === 'bad', `after reload state ${v.state} != bad (cookie did not stick)`);
  verify(v, 'reload');

  // ---- 2. no layout shift ------------------------------------------------
  await page.goto(BASE + '/admin/?comp=all', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#comp-card .comp-chip');
  const boxes = () => page.evaluate(() => {
    const out = {};
    document.querySelectorAll('.comp-chip').forEach(c => {
      const r = c.getBoundingClientRect();
      out[c.dataset.key] = { x: r.x, y: r.y, w: r.width };
    });
    return out;
  });
  const before = await boxes();
  await page.click('.comp-chip[data-key="human"] a.comp-tgl');
  const mid = await boxes();
  await page.click('.comp-chip[data-key="human"] a.comp-tgl');
  const after = await boxes();
  for (const k of Object.keys(before)) {
    for (const [label, snap] of [['off', mid], ['back-on', after]]) {
      const b = before[k], s = snap[k];
      if (Math.abs(b.x - s.x) > 0.5 || Math.abs(b.y - s.y) > 0.5 || Math.abs(b.w - s.w) > 0.5) {
        fails.push(`${k} moved after human ${label}: (${b.x},${b.y},w${b.w}) -> (${s.x},${s.y},w${s.w})`);
      }
    }
  }

  // ---- 3. breakdown popover, both homes ---------------------------------
  // In place (inside .comp-legend, where ".comp-legend span" once flattened
  // the rows), shown via :focus.
  await page.focus('.comp-chip[data-key="other"] .info-tip');
  const inPlace = await page.evaluate(() => {
    const pop = document.querySelector('.comp-chip[data-key="other"] .info-popup');
    const row = pop.querySelector('.orow');
    const d = pop.querySelector('.orow-d');
    return {
      visible: getComputedStyle(pop).display !== 'none',
      rowDisplay: row ? getComputedStyle(row).display : 'none',
      descDisplay: d ? getComputedStyle(d).display : 'none',
    };
  });
  ok(inPlace.visible, 'in-place popup not shown on focus');
  ok(inPlace.rowDisplay === 'flex', `in-place row display ${inPlace.rowDisplay} != flex`);
  ok(inPlace.descDisplay === 'block', `in-place desc display ${inPlace.descDisplay} != block`);

  // Pinned (a body-level clone that carries .info-popup on its root and
  // nothing else from the chip).
  await page.click('.comp-chip[data-key="other"] .info-tip');
  await page.waitForSelector('.info-popup-pinned', { timeout: 5000 });
  const pinned = await page.evaluate(() => {
    const clone = document.querySelector('.info-popup-pinned');
    const rows = clone.querySelectorAll('.orow');
    const d = clone.querySelector('.orow-d');
    const first = rows[0] ? getComputedStyle(rows[0]) : null;
    const rect = clone.getBoundingClientRect();
    return {
      rows: rows.length,
      rowDisplay: first ? first.display : 'none',
      rowJustify: first ? first.justifyContent : '',
      descDisplay: d ? getComputedStyle(d).display : 'none',
      width: rect.width,
      overflow: rect.right > innerWidth || rect.left < 0,
    };
  });
  ok(pinned.rows >= 3, `pinned clone has ${pinned.rows} rows`);
  ok(pinned.rowDisplay === 'flex', `pinned row display ${pinned.rowDisplay} != flex`);
  ok(pinned.rowJustify === 'space-between', `pinned row justify ${pinned.rowJustify}`);
  ok(pinned.descDisplay === 'block', `pinned desc display ${pinned.descDisplay} != block`);
  ok(pinned.width > 150 && pinned.width < 700, `pinned clone width ${pinned.width} looks broken`);
  ok(!pinned.overflow, 'pinned clone overflows the viewport');

  try {
    const clip = await page.evaluate(() => {
      const r = document.getElementById('comp-card').getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    });
    await page.screenshot({ path: OUT + '/comp-card.png', clip });
  } catch (_) { /* screenshots are artifacts, not assertions */ }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('comp-card: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
