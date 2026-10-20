// The reason badge opens the entry behind it in a popover.
//
// A custom rule's name can run to a sentence, and inline after the reason
// ("custom_rule · <the rule's name>") it stretched the hunt's badge column
// and the stats page's CAPTCHA-pass list.  The badge now names the reason
// alone; the entry -- the rule by name, linked to where it is set -- is
// rendered hidden beside it and opens on hover.  Two wirings, one per page:
// the hunt (and the realtime page) through the cell popover, the stats page
// through the help popover that already explains the reason, which gains the
// entry under its text.
//
// run.sh seeds a serve under a UA-filter preset (the hunt's badge) and a
// CAPTCHA pass under it (the stats page's pass list).  A preset rather than
// a custom rule: its name comes from the shipped list, while the custom-rules
// tab's tests own that list and start it empty.  The handler tests cover the
// custom rule's own case (its name, its link, a rule since deleted).
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const ENTRY_NAME = 'Empty UA / extremely short UA (5 chars or fewer)';
const ENTRY_LINK = '/admin/settings/ua-filter/';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

// hoverOpens: hover the marked element and report the visible popover's text
// and whether it links to the entry; null when none opened.  The wirings
// debounce by 150ms.
async function hoverOpens(page, sel) {
  await page.evaluate((s) => {
    document.querySelector(s).scrollIntoView({ block: 'center' });
  }, sel);
  await page.hover(sel);
  try {
    await page.waitForFunction((want) => {
      return Array.from(document.querySelectorAll('[data-popover]')).some(p =>
        getComputedStyle(p).display !== 'none' && (p.textContent || '').includes(want));
    }, { timeout: 4000 }, ENTRY_NAME);
  } catch (e) {
    return null;
  }
  return page.evaluate((link) => {
    const p = Array.from(document.querySelectorAll('[data-popover]'))
      .find(p => getComputedStyle(p).display !== 'none');
    return { text: p.textContent || '', linked: !!p.querySelector('a[href$="' + link + '"]') };
  }, ENTRY_LINK);
}

// markBadge: find the badge whose hidden note names the seeded entry, mark
// it for hovering, and report the badge's own text.
async function markBadge(page, badgeSel, noteClass) {
  return page.evaluate((bs, nc, name) => {
    const el = Array.from(document.querySelectorAll(bs)).find(b => {
      const n = b.nextElementSibling;
      return n && n.classList.contains(nc) && (n.textContent || '').includes(name);
    });
    if (!el) return null;
    el.setAttribute('data-e2e-badge', '1');
    return { text: el.textContent.trim(), noteHidden: el.nextElementSibling.offsetParent === null };
  }, badgeSel, noteClass, ENTRY_NAME);
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

  // (1) The hunt: the badge is the reason alone, the note hidden beside it,
  // and hovering opens the note with the entry linked to its tab.  Narrowed
  // to the seeded address: by the time this test runs, the tests before it
  // have written rows of their own, and a page of the unfiltered log no
  // longer reaches two minutes back.
  let resp = await page.goto(BASE + '/admin/hunt/?range=24h&ip=127.0.0.42', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);
  const hunt = await markBadge(page, 'table.events .fr-badge[data-fr-note]', 'fr-note');
  if (!hunt) {
    ok(false, 'hunt: no reason badge with the seeded preset behind it -- run.sh seeding or the range changed');
  } else {
    ok(hunt.text === 'ua_target', `hunt: the badge reads ${JSON.stringify(hunt.text)}, want the reason alone`);
    ok(hunt.noteHidden, 'hunt: the note must stay hidden until hovered');
    const pop = await hoverOpens(page, 'table.events .fr-badge[data-e2e-badge]');
    ok(pop, 'hunt: hovering the badge did not open a popover naming the preset');
    if (pop) ok(pop.linked, 'hunt: the popover does not link the preset to the UA filter tab');
  }

  // (2) The stats page's CAPTCHA-pass list: the same badge through the help
  // popover, which keeps the reason's own text above the entry.
  resp = await page.goto(BASE + '/admin/stats/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/stats/ status ${resp.status()}`);
  const stats = await markBadge(page, '.cp-fr[data-help-key="captcha_force.kind.ua_target"]', 'help-note');
  if (!stats) {
    ok(false, 'stats: no CAPTCHA-pass row with the seeded preset behind it -- run.sh seeding or the range changed');
  } else {
    ok(stats.text === 'ua_target', `stats: the badge reads ${JSON.stringify(stats.text)}, want the reason alone`);
    const pop = await hoverOpens(page, '.cp-fr[data-e2e-badge]');
    ok(pop, 'stats: hovering the badge did not open a popover naming the preset');
    if (pop) {
      ok(pop.linked, 'stats: the popover does not link the preset to the UA filter tab');
      ok(pop.text.includes('ua_target'), 'stats: the popover lost the reason\'s own explanation');
    }
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('force-badge-popover: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
