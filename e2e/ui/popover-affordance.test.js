// One marker for "this has a popover": a dotted underline.
//
// The affordances had grown per family -- help-dotted and ipclick were dotted,
// URL cells had their own copy of the same rule, and the cells whose popovers
// hold the most text (a clipped UA, a clamped ban reason) signalled nothing
// until the pointer happened to cross them.  A reader had to already know
// which cells answer to hovering.
//
// The rule now lives once in popover-pin.css on .cellpop-active, with the
// clamp wirings toggling an equivalent class off the same truncation check the
// popover itself uses.  Both directions matter: a value with a popover is
// underlined, and a short value with nothing more to show is NOT -- a marker
// on everything marks nothing.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

const dotted = s => s && s.line.indexOf('underline') >= 0 && s.style === 'dotted';

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const deco = sel => page.evaluate(sel => {
    const el = typeof sel === 'string' ? document.querySelector(sel) : null;
    if (!el) return null;
    const cs = getComputedStyle(el);
    return { line: cs.textDecorationLine, style: cs.textDecorationStyle };
  }, sel);

  // --- stats page: clipped UA cells are marked, short ones are not ---
  await page.goto(BASE + '/admin/stats/', { waitUntil: 'networkidle2' });
  const stats = await page.evaluate(() => {
    const cells = Array.from(document.querySelectorAll('table.cp-rankable td.bcd-ua.cellpop'))
      .filter(c => c.offsetParent !== null);
    const pick = c => {
      const cs = getComputedStyle(c);
      return { clipped: c.scrollWidth - c.clientWidth > 1,
               line: cs.textDecorationLine, style: cs.textDecorationStyle };
    };
    return {
      clipped: cells.filter(c => c.scrollWidth - c.clientWidth > 1).map(pick)[0] || null,
      short: cells.filter(c => c.scrollWidth - c.clientWidth <= 1).map(pick)[0] || null,
    };
  });
  ok(stats.clipped, 'no clipped UA cell on the stats page -- seeding changed');
  ok(dotted(stats.clipped), `a clipped UA carries no marker: ${JSON.stringify(stats.clipped)}`);
  if (stats.short) {
    ok(!dotted(stats.short), `a fully-visible UA is marked as having more: ${JSON.stringify(stats.short)}`);
  }

  // --- bans page: the clamped reason is marked, the short one is not ---
  await page.goto(BASE + '/admin/bans/', { waitUntil: 'networkidle2' });
  const bans = await page.evaluate(() => {
    const cells = Array.from(document.querySelectorAll('table.bans .clamp-v[data-full]'));
    const pick = c => {
      const cs = getComputedStyle(c);
      return { line: cs.textDecorationLine, style: cs.textDecorationStyle };
    };
    const long = cells.find(c => (c.dataset.full || '').indexOf('GSCAN_BEGIN') >= 0);
    const short = cells.find(c => (c.dataset.full || '') === 'scraper');
    return { long: long ? pick(long) : null, short: short ? pick(short) : null };
  });
  ok(bans.long, 'the seeded long ban reason is missing');
  ok(dotted(bans.long), `the clamped ban reason carries no marker: ${JSON.stringify(bans.long)}`);
  if (bans.short) {
    ok(!dotted(bans.short), `a fully-visible reason is marked: ${JSON.stringify(bans.short)}`);
  }

  // --- and the marker means what it says: hovering a marked cell opens ---
  const opened = await page.evaluate(async () => {
    const cell = document.querySelector('table.bans .clamp-v.clamp-active');
    if (!cell) return null;
    cell.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    await new Promise(r => setTimeout(r, 350));
    const pop = document.getElementById('clamp-popover');
    return !!pop && pop.offsetParent !== null;
  });
  ok(opened === true, 'a marked cell did not open its popover on hover');

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('popover-affordance: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
