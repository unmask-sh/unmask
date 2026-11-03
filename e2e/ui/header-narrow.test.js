// header-narrow: the top bar fits a phone held upright.
//
// At 390 px the bar used to run off the right edge: the page links broke one
// character per line, and the pickers, the bell and the account menu sat
// beyond the viewport, so a phone could reach none of them.  The bar wraps
// now (partial_header_tools.html): on every signed-in page the bar is no
// wider than the viewport, each page link stays on one line, and every
// tool of the bar -- ask, the host and site pickers, the bell, the account
// menu -- lies inside the viewport.  The same is read once more at 700 px,
// the narrow desktop the settings test uses.
const puppeteer = require('puppeteer-core');
const path = require('path');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

const PAGES = ['/admin/', '/admin/stats/', '/admin/hunt/', '/admin/bans/', '/admin/settings/', '/admin/profile/'];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
  });
  const page = await browser.newPage();
  page.errors = [];
  page.on('pageerror', e => page.errors.push(e.message));
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.evaluate(() => { document.cookie = 'unmask_locale=ja; path=/'; });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
  ok(/\/admin\/?$/.test(page.url()), 'login landed on ' + page.url());

  const read = () => page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const hdr = document.querySelector('header.unmask-header');
    const r = hdr ? hdr.getBoundingClientRect() : null;
    const tools = ['a.hdr-ask', '.host-picker', '.site-picker', '#nbell-btn', '#user-menu-btn'].map(sel => {
      const el = document.querySelector(sel);
      if (!el) return sel + ':missing';
      const b = el.getBoundingClientRect();
      return b.left >= 0 && b.right <= vw + 0.5 ? null : sel + ':' + Math.round(b.left) + '..' + Math.round(b.right);
    }).filter(Boolean);
    const links = Array.from(document.querySelectorAll('nav.nav a')).map(a => {
      const b = a.getBoundingClientRect();
      const lh = parseFloat(getComputedStyle(a).lineHeight) || parseFloat(getComputedStyle(a).fontSize) * 1.5;
      return b.height > lh * 1.6 ? a.textContent.trim() + ':' + Math.round(b.height) + 'px' : null;
    }).filter(Boolean);
    return {
      vw,
      header: !!hdr,
      overflow: hdr ? hdr.scrollWidth - hdr.clientWidth : -1,
      right: r ? Math.round(r.right) : -1,
      outside: tools,
      tallLinks: links,
      links: document.querySelectorAll('nav.nav a').length,
    };
  });

  for (const p of PAGES) {
    await page.goto(BASE + p, { waitUntil: 'networkidle2' });
    const m = await read();
    ok(m.header && m.vw <= 400, p + ': the page lays out at the phone width: ' + JSON.stringify(m));
    ok(m.overflow <= 0 && m.right <= m.vw + 0.5, p + ': the bar is wider than the viewport: ' + JSON.stringify(m));
    ok(m.outside.length === 0, p + ': tools of the bar outside the viewport: ' + JSON.stringify(m));
    ok(m.links === 5 && m.tallLinks.length === 0, p + ': a page link wraps inside itself: ' + JSON.stringify(m));
    if (SHOTS && p === '/admin/') {
      try { await page.screenshot({ path: path.join(SHOTS, 'header-narrow-390.png'), clip: { x: 0, y: 0, width: 390, height: 220 } }); } catch (e) {}
    }
  }

  // The bar's drop-downs -- the account menu, the notifications, the host
  // list -- still open, and open inside the viewport: anchored to their
  // button's right edge they ran off the left side at this width.
  await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  const popOf = sel => page.evaluate(s => {
    const el = document.querySelector(s);
    if (!el) return { missing: s };
    const b = el.getBoundingClientRect();
    return { s, shown: getComputedStyle(el).display !== 'none' && b.width > 0, left: Math.round(b.left), right: Math.round(b.right), vw: document.documentElement.clientWidth };
  }, sel);
  for (const [btn, pop] of [['#user-menu-btn', '#user-menu-pop'], ['#nbell-btn', '#nbell-pop'], ['.host-picker .hp-dd > summary', '.host-picker .hp-list']]) {
    if (!(await page.$(btn))) { ok(false, btn + ' is not on the page'); continue; }
    await page.tap(btn);
    const p = await popOf(pop);
    ok(p.shown && p.left >= 0 && p.right <= p.vw + 0.5, 'opened from ' + btn + ', the drop-down lies inside the viewport: ' + JSON.stringify(p));
    await page.keyboard.press('Escape');
    await page.mouse.click(200, 700);
  }

  // 700 px, a narrow desktop window: the same holds.
  await page.setViewport({ width: 700, height: 600 });
  await page.goto(BASE + '/admin/settings/', { waitUntil: 'networkidle2' });
  const d = await read();
  ok(d.overflow <= 0 && d.outside.length === 0 && d.tallLinks.length === 0, '700 px settings: ' + JSON.stringify(d));

  ok(page.errors.length === 0, 'page errors ' + page.errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.log('FAIL header-narrow:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok header-narrow');
})().catch(e => { console.log('FAIL header-narrow: ' + (e.stack || e)); process.exit(1); });
