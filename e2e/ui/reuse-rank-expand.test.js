// Browser-level check of "show more" on the stats page's cookie-reuse card.
// The card holds the CAPTCHA, PoW and re-bound rankings one under the other,
// each a heading, a table and (past ten rows) a button straight in the card.
// The button must open the ranking it sits under: it used to take the card's
// first table, so the PoW ranking's button toggled the CAPTCHA ranking and the
// PoW rows past the tenth never appeared (10-20).
//
// run.sh seeds sixteen PoW reuse rows and two CAPTCHA reuse rows, so the
// card has two tables and only the PoW one has a button.
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
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(String(e.message || e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"]'),
  ]);

  // The PoW section: from its heading to the next one, straight in the card.
  // Its button gets an id so the test can click it the way a visitor does.
  const state = async () => page.evaluate(() => {
    const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
    const heads = Array.from(document.querySelectorAll('.bcd-card h6.cp-h'));
    // The heading's own label: its first text node.  The "?" beside it holds
    // the section's explainer, and the CAPTCHA one mentions PoW too.
    const label = x => (x.firstChild && x.firstChild.nodeType === 3) ? x.firstChild.textContent : x.textContent;
    const h = heads.find(x => /PoW/.test(label(x)));
    if (!h) return { found: false, heads: heads.map(x => label(x).trim()) };
    let tbl = null, btn = null;
    for (let el = h.nextElementSibling; el && !el.matches('h6.cp-h'); el = el.nextElementSibling) {
      if (!tbl) tbl = el.matches('table.cp-rankable') ? el : el.querySelector('table.cp-rankable');
      if (!btn && el.matches('.cp-more')) btn = el;
    }
    if (btn) btn.id = 'ui-e2e-pow-more';
    const card = h.closest('.bcd-card');
    const others = Array.from(card.querySelectorAll('table.cp-rankable')).filter(t => t !== tbl);
    const rows = tbl ? Array.from(tbl.querySelectorAll('tbody tr')) : [];
    return {
      found: true,
      tables: others.length + (tbl ? 1 : 0),
      rows: rows.length,
      extra: rows.filter(r => r.classList.contains('cp-row-extra')).length,
      hidden: rows.filter(r => !vis(r)).length,
      expanded: !!(tbl && tbl.classList.contains('cp-expanded')),
      othersExpanded: others.filter(t => t.classList.contains('cp-expanded')).length,
      btn: btn ? btn.textContent.trim() : null,
      btnMore: btn ? btn.getAttribute('data-more') : null,
      btnLess: btn ? btn.getAttribute('data-less') : null,
      aria: btn ? btn.getAttribute('aria-expanded') : null,
    };
  });

  const resp = await page.goto(BASE + '/admin/stats/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp && resp.status() === 200, `stats page status ${resp && resp.status()}`);
  let s = await state();
  ok(s.found, `the PoW reuse ranking is on the page (headings: ${JSON.stringify(s.heads)})`);
  if (s.found) {
    ok(s.tables >= 2, `the card holds another ranking table above the PoW one (tables=${s.tables})`);
    ok(s.rows >= 11, `the PoW ranking has rows past the tenth (seed), got ${s.rows}`);
    ok(s.extra === s.rows - 10, `rows past the top 10 carry cp-row-extra: ${s.extra} of ${s.rows}`);
    ok(s.hidden === s.extra && !s.expanded, `rows past the top 10 are hidden by default (hidden=${s.hidden}, extra=${s.extra}, expanded=${s.expanded})`);
    ok(s.btn && s.btn === s.btnMore, `the section has its show-more button: ${JSON.stringify(s.btn)}`);
  }

  if (s.found && s.btn) {
    await page.click('#ui-e2e-pow-more');
    s = await state();
    ok(s.expanded && s.hidden === 0, `show more reveals the PoW rows (expanded=${s.expanded}, hidden=${s.hidden})`);
    ok(s.othersExpanded === 0, `the other rankings in the card stay as they were (expanded elsewhere: ${s.othersExpanded})`);
    ok(s.btn === s.btnLess && s.aria === 'true', `the button now offers the top 10: ${JSON.stringify(s.btn)} (aria-expanded=${s.aria})`);
    if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-expanded.png', fullPage: true });

    await page.click('#ui-e2e-pow-more');
    s = await state();
    ok(!s.expanded && s.hidden === s.extra && s.btn === s.btnMore, `back to the top 10 (expanded=${s.expanded}, hidden=${s.hidden}, btn=${JSON.stringify(s.btn)})`);
  }

  ok(jsErrors.length === 0, `page JS errors: ${jsErrors.join(' | ')}`);
  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('PASS reuse-rank-expand');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
