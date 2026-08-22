// Unpinning a popover must hand it back to the hover state, not strand it.
//
// The pinned -> hover return is deliberate ("click again = unpin only", not
// "fully close"), and handleClick implements it by re-showing the primary
// popover.  But it did that with showAt(), the low-level painter, instead of
// the showHover() path that also records WHICH trigger the popover now belongs
// to.  So the popover was on screen while the install's hoverShown flag was
// still false -- and every dismissal route consults that flag first:
// hideHover's grace timer calls reconcileHover, which returns immediately when
// hoverShown is false, and the mousemove watchdog bails on the same test.
//
// The result is a popover that no gesture can close.  Reachable in two clicks
// on the bot-hunt log: pin a phase, click it again, move away.
//
// Real mouse movement matters here: reconcileHover's ground truth is CSS
// :hover, which synthetic mouseenter/mouseleave events do not set.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

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

  // A phase pill in a visible row: the trigger the report came in on.  The log
  // is long, so scroll it under the pointer first -- page.mouse works in
  // viewport coordinates and a row below the fold simply is not there.
  const box = await page.evaluate(() => {
    const tr = Array.from(document.querySelectorAll('table.events tbody tr'))
      .find(r => r.style.display !== 'none' && r.querySelector('td:nth-child(5) .phase-pill'));
    if (!tr) return null;
    const pill = tr.querySelector('td:nth-child(5) .phase-pill');
    pill.scrollIntoView({ block: 'center' });
    const r = pill.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return null;
    if (r.top < 0 || r.bottom > window.innerHeight) return null;
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  });

  if (!box) {
    ok(false, 'no visible phase pill on the hunt page -- run.sh seeding changed');
  } else {
    const state = () => page.evaluate(() => {
      const p = document.getElementById('cell-popover');
      return {
        hover: !!(p && getComputedStyle(p).display !== 'none'),
        pins: document.querySelectorAll('.popover-clone').length,
      };
    });
    // Somewhere with no popover trigger under it.  Picked by hit-test rather
    // than guessed, so a layout change cannot quietly park the pointer on
    // another trigger and keep a popover alive for the wrong reason.
    const AWAY = await page.evaluate(() => {
      for (const y of [40, 200, 400, 600, 800]) {
        for (const x of [window.innerWidth - 6, 6]) {
          const el = document.elementFromPoint(x, y);
          if (!el) continue;
          if (el.closest('[data-popover], .phase-pill, .session-chain, td, th, a, button')) continue;
          return { x, y };
        }
      }
      return { x: 6, y: 6 };
    });

    // 1. hover opens it (200ms open delay in the wiring)
    await page.mouse.move(box.x, box.y);
    await sleep(500);
    ok((await state()).hover, 'hovering the phase pill opened no popover');

    // 2. click pins it
    await page.mouse.click(box.x, box.y);
    await sleep(800); // the click may fetch the recorded timeline first
    ok((await state()).pins === 1, 'clicking the phase pill did not pin a popover');

    // 3. a pinned popover survives leaving the trigger -- that is the point of pinning
    await page.mouse.move(AWAY.x, AWAY.y);
    await sleep(500);
    ok((await state()).pins === 1, 'the pinned popover vanished when the pointer left');

    // 4. clicking again unpins, and hands the popover back to the hover state
    await page.mouse.move(box.x, box.y);
    await sleep(300);
    await page.mouse.click(box.x, box.y);
    await sleep(800);
    const afterUnpin = await state();
    ok(afterUnpin.pins === 0, 'clicking a pinned popover again did not unpin it');
    ok(afterUnpin.hover, 'unpinning closed the popover outright (expected: returns to hover form)');

    // 5. THE REGRESSION: now that it is a hover popover again, leaving must close it.
    await page.mouse.move(AWAY.x, AWAY.y);
    await sleep(700); // 150ms grace + reconcile + margin
    const afterLeave = await state();
    ok(!afterLeave.hover,
      'the popover stayed on screen after unpinning and moving away -- it is stranded, ' +
      'because the unpin path re-showed it without recording the hover state that dismissal reads');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('unpin-rehover: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
