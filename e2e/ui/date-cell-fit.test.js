// The hunt date cell must hold its contents inside its own column.
//
// table.events is table-layout:fixed, so the th's width IS the column -- and
// td.at used to be white-space:nowrap with overflow visible, so anything that
// did not fit was not clipped, it was painted on top of the IP cell to its
// right.  That combination has no visible failure until it happens: on
// 2026-08-26 a host rename split the recorded host id in two, which switched
// on the host pill that normally never shows, and a ~9rem timestamp plus two
// 4rem badges went into 13rem of column.  The IP vanished underneath them.
//
// Two things changed.  The host id moved into the date popover (see
// dtPopHtml), and the cell now clips.  Clipping is the half that actually
// holds, because the width needed is a function of which monospace font the
// viewer's machine resolves, and that is not knowable from here: measured on
// the same page, the same timestamp is 121.6px under Noto Sans Mono CJK JP,
// 146.4px under DejaVu Sans Mono, and 162.1px on the CI runner.  A column
// sized for one of those overflows under another -- which is exactly how the
// first attempt at this fix passed locally and failed in CI.
//
// So the assertions are in two tiers: the cell must clip (true for any font),
// and the contents must fit as laid out (true for the fonts reachable here,
// and the reason nothing is cut in practice).  Fit is measured against the
// content box, not the border box -- eating the cell's right padding is
// already a badge touching its neighbour's text.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1500, height: 900 },
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

  const res = await page.evaluate(async () => {
    const tr = Array.from(document.querySelectorAll('table.events tbody tr'))
      .find(r => r.style.display !== 'none' && r.querySelector('td.at .site-badge'));
    if (!tr) return { missing: true };

    const at = tr.querySelector('td.at');
    const ip = tr.querySelector('td.ipclick');
    const badge = at.querySelector('.site-badge');
    const cs = getComputedStyle(at);

    // How far the cell's contents reach past where its content box ends.  Every
    // piece of the cell is an element (a <time> and the badge), so the children
    // are the whole story.
    const padRight = parseFloat(cs.paddingRight) || 0;
    const spill = () => {
      const limit = at.getBoundingClientRect().right - padRight;
      const reach = Math.max(...Array.from(at.children)
        .map(c => c.getBoundingClientRect().right));
      return { over: reach - limit, reach };
    };

    const asRendered = spill();
    const before = badge.textContent;
    // Long enough that the badge is held at its max-width rather than by its
    // text -- which makes this a measurement of the CSS cap, not of the seed.
    badge.textContent = 'very-long-vhost-name.example.com';
    void at.offsetWidth; // force layout
    const atCap = spill();
    const capWidth = badge.getBoundingClientRect().width;
    badge.textContent = before;

    // What the cell stopped showing has to be reachable from it.  Hover the
    // timestamp, wait past the 200ms open delay, and read the labelled rows
    // back out.  A synthetic mouseenter carries no coordinates, so the popover
    // opens at the origin -- irrelevant, the content is what is being read.
    const time = at.querySelector('time.js-datetime');
    let popSite = null;
    if (time) {
      time.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
      await new Promise(r => setTimeout(r, 450));
      const pop = document.getElementById('cell-popover');
      const k = pop && Array.from(pop.querySelectorAll('.dtpop-k'))
        .find(e => e.textContent.trim() === 'Site');
      if (k && k.nextElementSibling) popSite = k.nextElementSibling.textContent.trim();
    }

    return {
      popSite,
      overflow: cs.overflow,
      timeWidth: at.querySelector('time')
        ? at.querySelector('time').getBoundingClientRect().width : 0,
      atWidth: at.getBoundingClientRect().width,
      ipLeft: ip ? ip.getBoundingClientRect().left : null,
      asRendered, atCap, capWidth,
      badgeText: before.trim(),
    };
  });

  if (res.missing) {
    ok(false, 'no visible row with a site badge in its date cell -- run.sh seeding changed');
  } else {
    // Tier 1: the cell clips.  This is what makes an overflow a cut badge
    // instead of a badge sitting on top of the IP, and it does not depend on
    // which font resolved -- so it is the assertion that has to hold
    // everywhere, and the one to fix first if this test ever goes red.
    ok(res.overflow !== 'visible',
      `td.at has overflow:${res.overflow}; without clipping, anything too wide for ` +
      `this column is painted over the IP cell rather than cut`);

    // Tier 2: nothing is actually being cut here.  17rem at a 16px root.
    // Pinned tightly on purpose: a loose band is worse than none, because the
    // fit assertions below then report the symptom while the assertion meant
    // to name the cause stays quiet.  (The first attempt used a 200-280 band,
    // which the 208px it was meant to catch passed.)
    ok(res.atWidth >= 280 && res.atWidth <= 296,
      `the at column measured ${res.atWidth.toFixed(1)}px, want ~288px (18rem)`);

    ok(res.asRendered.over <= 1,
      `the date cell's contents run ${res.asRendered.over.toFixed(1)}px past its content box ` +
      `as rendered (timestamp ${res.timeWidth.toFixed(1)}px, badge "${res.badgeText}") -- ` +
      `the badge is being cut`);

    ok(res.atCap.over <= 1,
      `a site badge at its CSS max-width runs ${res.atCap.over.toFixed(1)}px past the content ` +
      `box (timestamp ${res.timeWidth.toFixed(1)}px); widen the at column or lower ` +
      `td.at .site-badge{max-width}`);

    // The cap has to actually bind, or the measurement above proved nothing
    // about long names -- it would just be measuring the seed again.  Pinned at
    // the override's own value (5rem) rather than "bigger than nothing": the
    // shared rule this overrides is 4rem = 64px, so any threshold below that
    // passes in exactly the case worth catching.
    ok(res.capWidth >= 68 && res.capWidth <= 76,
      `the site badge capped at ${res.capWidth.toFixed(1)}px, want ~72px (4.5rem); ` +
      `at 64px the date cell's override is gone and the shared 4rem rule is back`);

    // The site badge is the truncated half of a pair: the cell shows a clipped
    // name, the popover shows the whole one.  Both halves have to be there --
    // the column fitting because the value went missing would pass every
    // measurement above.
    ok(res.popSite === res.badgeText,
      `the date popover's Site row reads ${JSON.stringify(res.popSite)}, ` +
      `the row's badge reads ${JSON.stringify(res.badgeText)}`);

    if (res.ipLeft !== null) {
      ok(res.atCap.reach <= res.ipLeft + 1,
        `the date cell's contents reach ${(res.atCap.reach - res.ipLeft).toFixed(1)}px into ` +
        `the IP cell -- the 2026-08-26 symptom exactly`);
    }
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  // Print the numbers even when green.  Font metrics differ between this
  // machine and CI, so the margin -- not the pass -- is what says whether the
  // column has room to spare or is one font substitution away from spilling.
  if (!res.missing) {
    console.log(`date-cell-fit: OK (at ${res.atWidth.toFixed(1)}px, overflow:${res.overflow}; ` +
      `timestamp ${res.timeWidth.toFixed(1)}px; headroom as rendered ` +
      `${(-res.asRendered.over).toFixed(1)}px, at the badge's cap ` +
      `${(-res.atCap.over).toFixed(1)}px; badge capped at ${res.capWidth.toFixed(1)}px)`);
  } else {
    console.log('date-cell-fit: OK');
  }
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
