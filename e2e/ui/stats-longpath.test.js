// The stats page's recent-passes table survives a scanner-length path.
//
// The path column had no clip rule: td.bcd-clip's ellipsis is scoped to
// .bcd-twoflex, and this table was not in that family, so a pass whose
// orig_path was /en/calendar/2278...78 (a probe hundreds of characters long)
// stretched its row to the path's full width and the whole card scrolled
// sideways.  The table now joins bcd-twoflex -- it has exactly that family's
// shape, two long columns -- and the full path stays one hover away in the
// popover that was already wired on the cell.
//
// run.sh seeds a bv_captcha_only pass with a 165-character orig_path.
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

  const resp = await page.goto(BASE + '/admin/stats/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/stats/ status ${resp.status()}`);

  const res = await page.evaluate(async () => {
    const cell = Array.from(document.querySelectorAll('td.bcd-clip'))
      .find(c => (c.getAttribute('data-path') || '').indexOf('787878') >= 0);
    if (!cell) return { missing: true };
    const wrap = cell.closest('.bcd-cliptable-scroll');
    const geom = {
      clipped: cell.scrollWidth - cell.clientWidth > 1,
      wrapScrolls: wrap ? wrap.scrollWidth - wrap.clientWidth > 1 : false,
    };
    // The clip is only acceptable because the full value is one hover away.
    cell.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    await new Promise(r => setTimeout(r, 400));
    const pop = document.getElementById('cell-popover');
    const txt = pop ? (pop.textContent || '') : '';
    return {
      geom,
      path: cell.getAttribute('data-path'),
      popShown: !!pop && pop.offsetParent !== null,
      popHasWholePath: txt.indexOf('326/') >= 0 && txt.indexOf('/en/calendar/22') >= 0,
    };
  });

  if (res.missing) {
    ok(false, 'the seeded long-path pass is not on the stats page -- run.sh seeding changed');
  } else {
    ok(res.geom.clipped, 'the scanner-length path renders unclipped, stretching the row');
    ok(!res.geom.wrapScrolls,
      'the card scrolls sideways -- the path is still setting the table width');
    ok(res.popShown, 'hovering the clipped path opened no popover');
    ok(res.popHasWholePath,
      'the popover does not carry the whole path (head or tail missing)');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('stats-longpath: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
