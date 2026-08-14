// A ban reason can be an entire request line -- the honeypot records the path
// that tripped it, and a shell-injection probe's path is hundreds of
// percent-encoded characters.  The bans table is auto-layout, so one such row
// decides the reason column's width for every row and squeezes the rest of the
// table out of shape.
//
// So the reason is clamped and the whole value moves into a popover.  Two
// things have to hold: a long reason must not widen the table, and a short one
// must stay plain -- an affordance on a value that is already fully visible
// teaches the operator to click things that do nothing.
//
// run.sh seeds one of each.
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

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/bans/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/bans/ status ${resp.status()}`);

  const geo = await page.evaluate(() => {
    const cells = Array.from(document.querySelectorAll('table.bans .clamp-v[data-full]'));
    const longCell = cells.find(c => (c.dataset.full || '').indexOf('GSCAN_BEGIN') >= 0);
    const shortCell = cells.find(c => (c.dataset.full || '') === 'scraper');
    const table = document.querySelector('table.bans');
    return {
      seeded: cells.length,
      hasLong: !!longCell,
      hasShort: !!shortCell,
      longClipped: longCell ? longCell.scrollWidth > longCell.clientWidth + 1 : null,
      longWidth: longCell ? longCell.getBoundingClientRect().width : null,
      shortClipped: shortCell ? shortCell.scrollWidth > shortCell.clientWidth + 1 : null,
      tableWidth: table ? table.getBoundingClientRect().width : null,
      docWidth: document.documentElement.clientWidth,
      // The full value must survive in the DOM, or the popover has nothing to
      // show and the operator has lost the reason entirely.
      longFullLen: longCell ? (longCell.dataset.full || '').length : 0,
    };
  });

  ok(geo.hasLong, 'the seeded long-reason ban is not on the page -- run.sh seeding changed');
  ok(geo.hasShort, 'the seeded short-reason ban is not on the page');

  if (geo.hasLong) {
    ok(geo.longClipped === true, 'the long reason is not clamped -- it renders at full width');
    ok(geo.longFullLen > 200, `the full reason was truncated server-side (${geo.longFullLen} chars kept)`);
    // The clamp is worth nothing if the cell still runs off the page.
    ok(geo.tableWidth <= geo.docWidth + 1,
      `the table is wider than the page (${Math.round(geo.tableWidth)} > ${geo.docWidth})`);
  }
  if (geo.hasShort) {
    ok(geo.shortClipped === false, 'a short reason is being treated as clipped');
  }

  // Hovering the clamped cell opens the popover with the whole value in it.
  const hov = await page.evaluate(async () => {
    const cell = Array.from(document.querySelectorAll('table.bans .clamp-v[data-full]'))
      .find(c => (c.dataset.full || '').indexOf('GSCAN_BEGIN') >= 0);
    if (!cell) return { missing: true };
    const r = cell.getBoundingClientRect();
    cell.dispatchEvent(new MouseEvent('mouseenter', {
      bubbles: true, clientX: r.left + 5, clientY: r.top + 5,
    }));
    await new Promise(res => setTimeout(res, 350));
    const pop = document.getElementById('clamp-popover');
    const txt = pop ? (pop.textContent || '') : '';
    return {
      shown: !!pop && pop.offsetParent !== null,
      hasWholeValue: txt.indexOf('whoami') >= 0 && txt.indexOf('GSCAN_BEGIN') >= 0,
      cursor: getComputedStyle(cell).cursor,
    };
  });

  if (hov.missing) {
    ok(false, 'the long-reason cell disappeared before the hover check');
  } else {
    ok(hov.shown, 'hovering the clamped reason opened no popover');
    ok(hov.hasWholeValue, 'the popover does not carry the whole reason (the tail is missing)');
    ok(hov.cursor === 'help', `the clamped cell does not signal it is interactive (cursor: ${hov.cursor})`);
  }

  // A short reason stays inert: no popover, no pointer affordance.
  const quiet = await page.evaluate(async () => {
    // A real pointer leaves one cell before it enters the next; synthetic
    // events do not, so the previous popover has to be dismissed by hand or
    // this reads its leftovers as a popover the short cell opened.
    document.querySelectorAll('table.bans .clamp-v[data-full]').forEach(c => {
      c.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    });
    await new Promise(res => setTimeout(res, 100));

    const cell = Array.from(document.querySelectorAll('table.bans .clamp-v[data-full]'))
      .find(c => (c.dataset.full || '') === 'scraper');
    if (!cell) return { missing: true };
    const r = cell.getBoundingClientRect();
    cell.dispatchEvent(new MouseEvent('mouseenter', {
      bubbles: true, clientX: r.left + 5, clientY: r.top + 5,
    }));
    await new Promise(res => setTimeout(res, 350));
    const pop = document.getElementById('clamp-popover');
    return {
      shown: !!pop && pop.offsetParent !== null,
      cursor: getComputedStyle(cell).cursor,
    };
  });

  if (!quiet.missing) {
    ok(!quiet.shown, 'a short reason opened a popover it has nothing to put in');
    ok(quiet.cursor !== 'help', 'a short reason is advertising an interaction it does not have');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('bans-clamp: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
