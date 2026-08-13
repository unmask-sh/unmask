// Browser-level check that a hunt cell whose value the reader cannot see opens
// its popover.
//
// Two ways a cell hides its value, and the popover is the only way back to it:
//
//   - the user-agent column renders a SUMMARY ("Windows · Chrome") and carries
//     the raw string in data-full-value;
//   - the fingerprint column renders the value but the column is narrower than
//     it, so the browser truncates it.
//
// The second one used to be decided once, at DOMContentLoaded, by reading
// scrollWidth before layout had settled -- and these cells sit in an
// auto-layout table whose widths move as the web font swaps in.  A cell that
// IS truncated could be measured as fitting and never get a popover at all,
// leaving the value unreachable with nothing to indicate it was missing.  The
// check now runs at hover time.
//
// run.sh seeds a row with a long user-agent and a full-length JA4 for exactly
// these two cases.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

// hoverOpens: hover the marked cell and report whether a popover carrying
// `expect` appeared.  The wiring debounces by 200ms.
async function hoverOpens(page, sel, expect) {
  // Scroll it under the mouse first: puppeteer hovers a real pointer at the
  // element's clickable point, which does not exist for a row below the fold.
  await page.evaluate((s) => {
    document.querySelector(s).scrollIntoView({ block: 'center' });
  }, sel);
  await page.hover(sel);
  try {
    // Scan every [data-popover]: the page carries more than one (the hover
    // popover and the pin template), and the first in document order is the
    // hidden one.
    await page.waitForFunction((want) => {
      return Array.from(document.querySelectorAll('[data-popover]')).some(p =>
        getComputedStyle(p).display !== 'none' && (p.textContent || '').includes(want));
    }, { timeout: 4000 }, expect);
    return true;
  } catch (e) {
    return false;
  }
}

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

  // (1) Summarised value: the cell shows "Windows · Chrome", the raw UA lives
  // in data-full-value, so the popover is the only route to it.
  const uaFound = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('table.events td.ua.cellpop'))
      .find(c => (c.getAttribute('data-full-value') || '').includes('UI-E2E-longua-padding'));
    if (!el) return false;
    el.setAttribute('data-e2e-ua', '1');
    return true;
  });
  if (!uaFound) {
    ok(false, 'the seeded long-UA row is not on the page -- run.sh seeding or the range changed');
  } else {
    ok(await hoverOpens(page, 'table.events td[data-e2e-ua]', 'UI-E2E-longua-padding'),
      'a summarised user-agent cell did not open a popover carrying the raw value');
  }

  // (2) Truncated value: no data-full-value, so whether the popover exists
  // depends entirely on the clip check -- the path that used to be decided too
  // early and silently lose the popover.
  const clip = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('table.events td.mono.cellpop'))
      .find(c => !c.getAttribute('data-full-value') &&
                 c.textContent.includes('t13d1516h2') &&
                 c.scrollWidth - c.clientWidth > 1);
    if (!el) return { missing: true };
    el.setAttribute('data-e2e-clip', '1');
    return { active: el.classList.contains('cellpop-active'), text: el.textContent.trim() };
  });
  if (clip.missing) {
    ok(false, 'no truncated fingerprint cell on the page -- the seed or the column width changed, ' +
      'so the clip path is untested');
  } else {
    ok(clip.active, 'a truncated cell did not get the cellpop-active affordance');
    ok(await hoverOpens(page, 'table.events td[data-e2e-clip]', 't13d1516h2'),
      'hovering a truncated cell did not open a popover');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('cellpop: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
