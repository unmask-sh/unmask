// A hover popover must survive the journey into it.
//
// It opens 12px below the pointer, so the natural next gesture -- moving into
// the popover to read or copy the clipped value it exists to show -- begins by
// leaving the trigger cell.  Every wiring hid the popover on that first pixel,
// which made it unreachable: hold the pointer still and it stays, drift toward
// it and it vanishes.  Reported on the PoW cookie-reuse ranking as "the UA is
// clipped but the popover sometimes doesn't appear" -- the sometimes was
// whether the reporter's hand moved.
//
// hideHover now grants a 150ms grace and then asks the same :hover ground
// truth the mousemove reconciler always used: pointer on the popover (or back
// on the trigger) keeps it, anywhere else hides it.
//
// run.sh seeds 14 PoW cookie-reuse rows with clipped UAs.
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

  // Shown is not enough: with the immediate hide this test exists to prevent,
  // the pointer's journey crosses the NEXT row's UA cell, whose own popover
  // then opens -- a popover is visible, but it is the wrong row's.  So every
  // check also asks WHOSE value is on display.
  const popState = () => page.evaluate(() => {
    const p = document.getElementById('cell-popover');
    return { shown: !!p && p.offsetParent !== null, text: p ? (p.textContent || '') : '' };
  });

  const box = await page.evaluate(() => {
    const cell = Array.from(document.querySelectorAll('table.cp-rankable td.bcd-ua.cellpop'))
      .find(c => c.offsetParent !== null && c.scrollWidth - c.clientWidth > 1);
    if (!cell) return null;
    cell.scrollIntoView({ block: 'center' });
    const r = cell.getBoundingClientRect();
    // The tail of the UA is the part the clip hides -- exactly what the
    // popover exists to show, and unique per seeded row (rowNN).
    const ua = cell.textContent.trim();
    return { x: r.left + 40, y: r.top + r.height / 2, bot: r.bottom, tail: ua.slice(-6) };
  });
  if (!box) {
    ok(false, 'no clipped UA cell in the reuse ranking -- run.sh seeding changed');
  } else {
    // Hover, wait for the popover.
    await page.mouse.move(box.x, box.y - 100);
    await new Promise(r => setTimeout(r, 120));
    await page.mouse.move(box.x, box.y, { steps: 3 });
    await new Promise(r => setTimeout(r, 420));
    let st = await popState();
    ok(st.shown, 'the popover did not open on hover');
    ok(st.text.indexOf(box.tail) >= 0,
      `the popover does not show the hovered row (want ...${box.tail})`);

    // Where the popover actually is -- the journey's destination is its rect,
    // not a guessed offset.
    const onPop = await page.evaluate(() => {
      const p = document.getElementById('cell-popover');
      const r = p.getBoundingClientRect();
      return { x: r.left + Math.min(60, r.width / 2), y: r.top + Math.min(18, r.height / 2) };
    });

    // The reported gesture: leave the cell and travel into the popover.
    await page.mouse.move(onPop.x, onPop.y, { steps: 6 });
    await new Promise(r => setTimeout(r, 300));
    st = await popState();
    ok(st.shown, 'the popover vanished while the pointer travelled into it');
    ok(st.text.indexOf(box.tail) >= 0,
      `arriving on the popover, it shows a different row's value (want ...${box.tail}) -- ` +
      'the original hid and a neighbouring cell reopened it');

    // Leaving the popover for open ground still dismisses it -- the grace must
    // not have turned the popover permanent.
    await page.mouse.move(8, 8, { steps: 8 });
    await new Promise(r => setTimeout(r, 350));
    ok(!(await popState()).shown, 'the popover stayed after the pointer left it entirely');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('hover-popover-reach: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
