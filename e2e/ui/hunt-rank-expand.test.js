// Browser-level check of the ranking cards' "show all" (replacing the 18rem
// scroll box): a card shows its top 10 rows, a button reveals the rest and
// remembers the choice in this browser, and no card scrolls -- the classic
// scrollbar was what narrowed the ASN card.
//
// run.sh seeds twelve public addresses with one serve each, so the IP
// ranking has 12 rows (plus the hammer on top).
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

  const state = async () => page.evaluate(() => {
    const card = document.querySelector('.rank-card-ip');
    const btn = card && card.querySelector('.rank-expand');
    const rows = card ? Array.from(card.querySelectorAll('tbody tr')) : [];
    const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
    const scroll = card && card.querySelector('.rank-scroll');
    return {
      rows: rows.length,
      hidden: rows.filter(r => !vis(r)).length,
      more: rows.filter(r => r.classList.contains('rank-more')).length,
      btn: btn ? btn.textContent.trim() : null,
      btnMore: btn ? btn.getAttribute('data-more') : null,
      btnLess: btn ? btn.getAttribute('data-less') : null,
      expanded: !!(card && card.classList.contains('expanded')),
      overflowY: scroll ? getComputedStyle(scroll).overflowY : null,
      scrolls: scroll ? scroll.scrollHeight > scroll.clientHeight + 1 : null,
    };
  });

  const resp = await page.goto(BASE + '/admin/hunt/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp && resp.status() === 200, `hunt page status ${resp && resp.status()}`);
  let s = await state();
  ok(s.rows >= 12, `IP ranking should have >= 12 rows (seed), got ${s.rows}`);
  ok(s.more === s.rows - 10, `rows past the top 10 carry rank-more: ${s.more} of ${s.rows}`);
  ok(s.hidden === s.more && !s.expanded, `rows past the top 10 are hidden by default (hidden=${s.hidden}, more=${s.more}, expanded=${s.expanded})`);
  ok(s.btn === s.btnMore && /\b1[0-9]\b|\b[2-9][0-9]\b/.test(s.btn || ''), `button offers the full count: ${JSON.stringify(s.btn)}`);
  ok(s.overflowY !== 'auto' && s.overflowY !== 'scroll' && s.scrolls === false, `no scroll box on the card (overflow-y=${s.overflowY}, scrolls=${s.scrolls})`);

  if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-top10.png', clip: { x: 0, y: 0, width: 1500, height: 700 } });
  await page.click('.rank-card-ip .rank-expand');
  s = await state();
  ok(s.expanded && s.hidden === 0, `show all reveals every row (expanded=${s.expanded}, hidden=${s.hidden})`);
  if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-all.png', clip: { x: 0, y: 0, width: 1500, height: 900 } });
  ok(s.btn === s.btnLess, `button now offers the top 10: ${JSON.stringify(s.btn)}`);

  await page.reload({ waitUntil: 'networkidle2' });
  s = await state();
  ok(s.expanded && s.hidden === 0, `the choice survives a reload (expanded=${s.expanded}, hidden=${s.hidden})`);

  await page.click('.rank-card-ip .rank-expand');
  s = await state();
  ok(!s.expanded && s.hidden === s.more && s.btn === s.btnMore, `back to the top 10 (expanded=${s.expanded}, hidden=${s.hidden})`);

  // The fold button still works alongside the expand button.
  await page.click('.rank-card-ip .rank-fold');
  const folded = await page.evaluate(() => document.querySelector('.rank-card-ip').classList.contains('folded'));
  ok(folded, 'the fold button still folds the card');
  await page.click('.rank-card-ip .rank-fold');

  ok(jsErrors.length === 0, `page JS errors: ${jsErrors.join(' | ')}`);
  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('PASS hunt-rank-expand');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
