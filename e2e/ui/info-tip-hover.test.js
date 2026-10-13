// The "?" beside a tile's label opens its help on hover, on the realtime page
// as on the dashboard.  The realtime tiles' label clipped itself
// (overflow:hidden, for the ellipsis), which clipped the hover popup inside it
// too: the help showed only when clicked, through the pinned copy that lives
// on <body>.  So each tip is hovered and the popup must be what the pointer
// would hit below the label -- a clipped popup still has its full box, but is
// not on top there.  And the label still has to fit its tile, the ellipsis now
// being the text's.
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

  for (const [path, tile] of [['/admin/live/', '.live'], ['/admin/', '.kpi']]) {
    const sel = tile + ' .label .info-tip';
    const resp = await page.goto(BASE + path, { waitUntil: 'networkidle2' });
    ok(resp.status() === 200, `${path} status ${resp.status()}`);
    const n = await page.$$eval(sel, els => els.length);
    ok(n >= 2, `${path}: ${n} tile tips, expected the tiles' help`);
    for (let i = 0; i < n; i++) {
      await page.evaluate((sel, i) => {
        document.querySelectorAll(sel)[i].scrollIntoView({ block: 'center' });
      }, sel, i);
      const tips = await page.$$(sel);
      await tips[i].hover();
      await sleep(150);
      const r = await page.evaluate((sel, i) => {
        const tip = document.querySelectorAll(sel)[i];
        const label = tip.closest('.label');
        const pop = tip.querySelector('.info-popup');
        const pr = pop.getBoundingClientRect();
        const lr = label.getBoundingClientRect();
        // a point well inside the popup and below the label's box
        const x = pr.left + Math.min(24, pr.width / 2);
        const y = Math.max(pr.top + pr.height * 0.6, lr.bottom + 4);
        const hit = document.elementFromPoint(x, y);
        return {
          name: label.textContent.replace(tip.textContent, '').trim(),
          shown: getComputedStyle(pop).display !== 'none',
          onTop: !!hit && pop.contains(hit),
        };
      }, sel, i);
      ok(r.shown && r.onTop, `${path}: the help of "${r.name}" does not show on hover (shown ${r.shown}, on top ${r.onTop})`);
      await page.mouse.move(5, 5);
    }
    const spill = await page.$$eval(tile + ' .label', (els, tile) => els
      .filter(l => l.getBoundingClientRect().right > l.closest(tile).getBoundingClientRect().right + 1)
      .map(l => l.textContent.trim().slice(0, 30)), tile);
    ok(spill.length === 0, `${path}: labels spill out of their tile: ${spill.join(' | ')}`);
  }
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('info-tip-hover: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
