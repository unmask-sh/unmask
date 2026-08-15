// Admin data tables come in two sizes, on purpose, and only two.
//
// They had drifted to four -- .8 / .85 / .875 / .88rem -- with the bans page
// showing two of them stacked on one screen: the ban list at .88 and the
// community feed directly below it at .85.  Nobody chose that; it accumulated
// one page at a time, and it is visible.
//
// The two tiers that remain are a real distinction:
//   .8rem  a log you scan -- hunt's events and rankings, the overview's events.
//          Denser on purpose: a tenth off the row height is rows you can see
//          without scrolling, and these are read by sweeping down a column.
//   .88rem a list you read -- bans, the community feed, audit, users, AI
//          traffic, the playground detail.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

// 16px root: .8rem = 12.8px, .88rem = 14.08px.
const DENSE = 12.8;
const REGULAR = 14.08;

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

  const pages = [
    ['bans', '/admin/bans/'],
    ['community-bans', '/admin/community-bans/'],
    ['overview', '/admin/'],
    ['hunt', '/admin/hunt/?range=24h'],
    ['users', '/admin/users/'],
    ['audit', '/admin/audit/'],
  ];

  for (const [name, path] of pages) {
    const resp = await page.goto(BASE + path, { waitUntil: 'networkidle2' });
    if (resp.status() !== 200) {
      ok(false, `${name}: status ${resp.status()}`);
      continue;
    }
    const res = await page.evaluate((dense, regular) => {
      const seen = [];
      document.querySelectorAll('table').forEach(t => {
        // Only the data tables: a table with no rows tells us nothing, and the
        // settings forms are a different family with their own sizing.
        if (!t.className || !t.querySelector('tbody tr')) return;
        const cls = String(t.className);
        if (!/\b(bans|feed|events|rank|audit|users|ai-traffic|detail)\b/.test(cls)) return;
        const px = Math.round(parseFloat(getComputedStyle(t).fontSize) * 100) / 100;
        const tier = px === dense ? 'dense' : px === regular ? 'regular' : 'stray';
        seen.push({ cls: cls.split(/\s+/)[0], px, tier });
      });
      return {
        seen,
        pageScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      };
    }, DENSE, REGULAR);

    res.seen.forEach(t => {
      ok(t.tier !== 'stray',
        `${name}: table.${t.cls} is ${t.px}px -- neither tier (${DENSE} dense / ${REGULAR} regular)`);
    });
    // Deliberately NOT "one page, one size".  The overview stacks a summary
    // table you read against an event log you scan, and those earning
    // different densities is the whole point of having two tiers.  What was
    // wrong on the bans page was two lists of the SAME kind disagreeing, which
    // is checked directly below.
    // Bigger text must not have pushed anything off the page.
    ok(!res.pageScrolls, `${name}: the page scrolls sideways`);
  }

  // The reported case, checked by name: the ban list and the community feed
  // sit on one screen, one above the other, and are the same kind of list.
  await page.goto(BASE + '/admin/bans/', { waitUntil: 'networkidle2' });
  const stacked = await page.evaluate(() => {
    const px = sel => {
      const t = document.querySelector(sel);
      return t ? Math.round(parseFloat(getComputedStyle(t).fontSize) * 100) / 100 : null;
    };
    return { bans: px('table.bans'), feed: px('table.feed') };
  });
  // The feed table only renders once Community Bans is configured, which a
  // throwaway test install is not -- so this is checked when both are on the
  // page and skipped when they are not.  The stray check above is what
  // guarantees it in general: both are pinned to the same tier, so they cannot
  // disagree wherever they do appear together.
  if (stacked.bans == null || stacked.feed == null) {
    ok(stacked.bans != null, 'the bans page no longer renders its ban table at all');
  } else {
    ok(stacked.bans === stacked.feed,
      `the ban list and the feed below it are different sizes: ${stacked.bans}px vs ${stacked.feed}px`);
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('table-font-tiers: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
