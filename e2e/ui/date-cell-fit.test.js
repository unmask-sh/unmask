// The hunt date cell must hold its contents inside its own column.
//
// table.events is table-layout:fixed, so the th's width IS the column -- and
// td.at is white-space:nowrap with no overflow:hidden, so anything that does
// not fit is not clipped, it is painted on top of the IP cell to its right.
// That combination has no visible failure until it happens: on 2026-08-26 a
// host rename split the recorded host id in two, which switched on the host
// pill that normally never shows, and a ~9rem timestamp plus two 4rem badges
// went into 13rem of column.  The IP vanished underneath them.
//
// The host id now lives in the date popover instead (see dtPopHtml), and the
// column is 15rem.  A string check pins those two facts; this measures whether
// they are actually enough, in a browser, with layout resolved -- which is the
// only place the question has an answer.
//
// It measures twice: as rendered, and with the site badge pushed to the width
// the CSS lets it reach.  The second is the bound that matters, because the
// seeded site names are short and the real ones are not.
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

    // How far the cell's contents reach past the cell's own right edge.  Every
    // piece of the cell is an element (a <time> and the badge), so the children
    // are the whole story.
    const spill = () => {
      const right = at.getBoundingClientRect().right;
      const reach = Math.max(...Array.from(at.children)
        .map(c => c.getBoundingClientRect().right));
      return { over: reach - right, reach };
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
      atWidth: at.getBoundingClientRect().width,
      ipLeft: ip ? ip.getBoundingClientRect().left : null,
      asRendered, atCap, capWidth,
      badgeText: before.trim(),
    };
  });

  if (res.missing) {
    ok(false, 'no visible row with a site badge in its date cell -- run.sh seeding changed');
  } else {
    // 15rem at a 16px root.  Pinned tightly on purpose: a loose band is worse
    // than none, because the overflow assertions below then report the symptom
    // while the assertion meant to name the cause stays quiet.  (Measured: the
    // old 13rem is 208px and passed a 200-280 band.)
    ok(res.atWidth >= 232 && res.atWidth <= 248,
      `the at column measured ${res.atWidth.toFixed(1)}px, want ~240px (15rem)`);

    ok(res.asRendered.over <= 1,
      `the date cell overflows by ${res.asRendered.over.toFixed(1)}px as rendered ` +
      `(badge "${res.badgeText}") -- it has no overflow:hidden, so that is drawn over the IP`);

    ok(res.atCap.over <= 1,
      `a site badge at its CSS max-width pushes the date cell ${res.atCap.over.toFixed(1)}px ` +
      `past its column; widen the at column or lower td.at .site-badge{max-width}`);

    // The cap has to actually bind, or the measurement above proved nothing
    // about long names -- it would just be measuring the seed again.  Pinned at
    // the override's own value (5rem) rather than "bigger than nothing": the
    // shared rule this overrides is 4rem = 64px, so any threshold below that
    // passes in exactly the case worth catching.
    ok(res.capWidth >= 76 && res.capWidth <= 84,
      `the site badge capped at ${res.capWidth.toFixed(1)}px, want ~80px (5rem); ` +
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
    console.log(`date-cell-fit: OK (at ${res.atWidth.toFixed(1)}px; ` +
      `headroom as rendered ${(-res.asRendered.over).toFixed(1)}px, ` +
      `at the badge's cap ${(-res.atCap.over).toFixed(1)}px; ` +
      `badge capped at ${res.capWidth.toFixed(1)}px)`);
  } else {
    console.log('date-cell-fit: OK');
  }
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
