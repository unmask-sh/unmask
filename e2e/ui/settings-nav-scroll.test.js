// The settings nav stays in view and scrolls on its own.
//
// The nav holds more entries than a typical viewport is tall.  It used to move
// with the page, which left its upper entries out of reach from the lower part
// of a long tab.  Against a real running admin, this checks that:
//   - on a short viewport the nav is a scroller that never reaches under the
//     fold, at the top of the page (where it starts below the header) and
//     further down (where it sticks);
//   - every entry can be reached by scrolling the nav alone, and a wheel over
//     the nav moves the nav, not the page -- also at the nav's end;
//   - a tab change, which is a page load, keeps the nav where it was, and a
//     direct arrival brings the active entry into view;
//   - a nav that fits (a tall viewport) lets the wheel through to the page;
//   - the narrow layout, where the nav sits above the content, is not clipped.
//
// Driven by run.sh (throwaway admin). Env: UI_E2E_BASE, UI_E2E_USER,
// UI_E2E_PASS, CHROME_BIN, UI_E2E_OUT.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
// A tab several viewports long on a fresh install, so the page itself scrolls.
const LONG_TAB = '/admin/settings/theme/';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// What the nav looks like right now, in viewport coordinates.
const look = page => page.evaluate(() => {
  const nav = document.querySelector('.settings-shell > .settings-nav');
  const links = [...nav.querySelectorAll('a')];
  const r = nav.getBoundingClientRect();
  const box = el => { const b = el.getBoundingClientRect(); return { top: b.top, bottom: b.bottom }; };
  const cs = getComputedStyle(nav);
  return {
    top: r.top, bottom: r.bottom, vh: window.innerHeight, scrollY: window.scrollY,
    navScroll: nav.scrollTop, navMax: nav.scrollHeight - nav.clientHeight,
    scrolls: nav.classList.contains('scrolls'),
    overscroll: cs.overscrollBehaviorY, position: cs.position, maxHeight: cs.maxHeight, overflowY: cs.overflowY,
    first: box(links[0]), last: box(links[links.length - 1]),
    active: nav.querySelector('a.active') ? box(nav.querySelector('a.active')) : null,
    lastHref: links[links.length - 1].getAttribute('href'),
    pageRoom: document.documentElement.scrollHeight - window.innerHeight,
  };
});
// Inside the nav's own box, and so inside the viewport when the nav is.
const within = (b, v) => b && b.top >= v.top - 1 && b.bottom <= v.bottom + 1;
const until = async (page, fn, ms = 3000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(50)) {
    if (await page.evaluate(fn)) return true;
  }
  return false;
};
// Reads the nav until it looks as `want` says, or for 3 s: the scroll event
// that refits the nav comes a frame after the scroll itself.
const settle = async (page, want) => {
  for (const end = Date.now() + 3000; ; await sleep(50)) {
    const v = await look(page);
    if (want(v) || Date.now() > end) return v;
  }
};
const navScrolled = () => document.querySelector('.settings-shell > .settings-nav').scrollTop > 0;
const pageScrolled = () => window.scrollY > 0;
const overNav = async page => {
  const v = await look(page);
  await page.mouse.move(100, (Math.max(v.top, 0) + Math.min(v.bottom, v.vh)) / 2);
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 600 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // ---- short viewport, top of the page: a scroller that ends above the fold ----
  await page.goto(BASE + '/admin/settings/', { waitUntil: 'networkidle2' });
  let v = await look(page);
  ok(v.navMax > 50, `600px viewport: the nav has nothing to scroll (max ${v.navMax}) -- the test needs a nav taller than the viewport`);
  ok(v.scrolls, 'a nav with something to scroll is not marked .scrolls');
  ok(v.overscroll === 'contain', `overscroll-behavior of a scrolling nav is ${v.overscroll}, want contain`);
  ok(v.scrollY === 0 && v.top > 16, `expected the unscrolled page with the nav below the header (scrollY ${v.scrollY}, nav top ${v.top})`);
  ok(v.bottom <= v.vh, `top of the page: the nav reaches under the fold (bottom ${v.bottom}, viewport ${v.vh})`);
  ok(within(v.active, v), 'top tab: the active entry is not visible');

  // ---- a wheel over the nav moves the nav, not the page ----
  await overNav(page);
  await page.mouse.wheel({ deltaY: 240 });
  ok(await until(page, navScrolled), 'a wheel over the nav did not scroll the nav');
  v = await look(page);
  ok(v.scrollY === 0, `a wheel over the nav scrolled the page (scrollY ${v.scrollY})`);

  // ---- the last entry is reachable by the nav alone; at the end the wheel stops there ----
  await page.evaluate(() => { const n = document.querySelector('.settings-shell > .settings-nav'); n.scrollTop = n.scrollHeight; });
  v = await look(page);
  ok(within(v.last, v) && v.last.bottom <= v.vh, `the last entry is not in view with the nav scrolled to its end (entry ${JSON.stringify(v.last)}, nav ${v.top}..${v.bottom}, viewport ${v.vh})`);
  await overNav(page);
  await page.mouse.wheel({ deltaY: 400 });
  await sleep(600);
  v = await look(page);
  ok(v.scrollY === 0, `a wheel at the nav's end went on to scroll the page (scrollY ${v.scrollY})`);

  // ---- a tab change keeps the nav where it was ----
  const before = v.navScroll;
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.evaluate(() => { const l = document.querySelectorAll('.settings-shell > .settings-nav a'); l[l.length - 1].click(); }),
  ]);
  v = await look(page);
  ok(page.url().endsWith(v.lastHref), `the click did not land on the last tab (${page.url()})`);
  ok(Math.abs(v.navScroll - before) <= 2, `the nav moved across the tab change (${before} -> ${v.navScroll})`);
  ok(within(v.active, v) && v.active.bottom <= v.vh, 'after the tab change the active entry is not visible');
  ok(v.scrollY === 0, `bringing the active entry into view scrolled the page (scrollY ${v.scrollY})`);
  const lastTab = page.url();

  // ---- a direct arrival, no kept position: the active entry is brought into view ----
  await page.evaluate(() => sessionStorage.clear());
  await page.goto('about:blank');
  await page.goto(lastTab, { waitUntil: 'networkidle2' });
  v = await look(page);
  ok(v.navScroll > 0, 'direct arrival on the last tab: the nav stayed at its top');
  ok(within(v.active, v) && v.active.bottom <= v.vh, 'direct arrival on the last tab: the active entry is not visible');
  ok(v.scrollY === 0, `direct arrival scrolled the page (scrollY ${v.scrollY})`);

  // ---- further down a long tab: the nav sticks, fills the room, and its top is reachable ----
  await page.goto(BASE + LONG_TAB, { waitUntil: 'networkidle2' });
  v = await look(page);
  ok(v.pageRoom > 400, `${LONG_TAB} is not long enough to scroll the page (room ${v.pageRoom})`);
  await page.evaluate(() => window.scrollTo(0, 400));
  v = await settle(page, v => Math.abs(v.top - 16) <= 1 && v.bottom >= v.vh - 17);
  ok(Math.abs(v.top - 16) <= 1, `scrolled page: the nav is not stuck 1rem below the top (top ${v.top})`);
  ok(v.bottom <= v.vh && v.bottom >= v.vh - 17, `scrolled page: the nav does not fill the room to 1rem above the fold (bottom ${v.bottom}, viewport ${v.vh})`);
  await page.evaluate(() => { document.querySelector('.settings-shell > .settings-nav').scrollTop = 0; });
  v = await look(page);
  ok(within(v.first, v) && v.first.top >= 0, 'scrolled page: the first entry is not reachable by scrolling the nav');
  // ...and at the very bottom of the page the nav is not pushed out of place.
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  v = await settle(page, v => v.scrollY > 400 && Math.abs(v.top - 16) <= 1 && v.bottom <= v.vh);
  ok(Math.abs(v.top - 16) <= 1 && v.bottom <= v.vh, `bottom of the page: the nav left its place (top ${v.top}, bottom ${v.bottom}, viewport ${v.vh})`);

  // ---- a tall viewport: the nav fits and lets the wheel through ----
  await page.setViewport({ width: 1360, height: 1500 });
  await page.goto(BASE + LONG_TAB, { waitUntil: 'networkidle2' });
  v = await look(page);
  ok(v.navMax <= 1, `1500px viewport: the nav still scrolls (max ${v.navMax})`);
  ok(!v.scrolls && v.overscroll !== 'contain', `a nav that fits is marked as scrolling (.scrolls ${v.scrolls}, overscroll ${v.overscroll})`);
  if (v.pageRoom > 100) {
    await overNav(page);
    await page.mouse.wheel({ deltaY: 240 });
    ok(await until(page, pageScrolled), 'a wheel over a nav that fits did not scroll the page');
  } else {
    fails.push(`1500px viewport: ${LONG_TAB} leaves the page nothing to scroll (room ${v.pageRoom}); pick a longer tab`);
  }

  // ---- the narrow layout: the nav sits above the content, unclipped ----
  await page.setViewport({ width: 700, height: 600 });
  await page.goto(BASE + '/admin/settings/', { waitUntil: 'networkidle2' });
  v = await look(page);
  ok(v.position === 'static' && v.maxHeight === 'none' && v.overflowY === 'visible',
     `narrow layout: the nav is ${v.position} / max-height ${v.maxHeight} / overflow-y ${v.overflowY}, want static / none / visible`);
  ok(v.navMax <= 1, `narrow layout: the nav is clipped (hidden ${v.navMax}px)`);

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('settings-nav-scroll: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
