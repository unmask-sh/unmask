// A hunt view filtered to the passes must be able to say where each session
// came from.
//
// The Referer is recorded on the serve -- the request that was challenged --
// and on nothing after it: the beacons are sent by the challenge page and
// would only name the site itself.  Filter the log to the passes and the
// serves are gone, so every session in the view used to read "referer: -".
// That is the mark for "the visitor sent none", shown on rows where the truth
// was "the row that knows is not on this page".
//
// The phase cell's click already fetches the session as the server recorded
// it.  That read now carries the referer, and settles the row's state so the
// date popover -- which is where the referer has always been shown -- agrees
// with it.  Until the click, the row says it has not looked, and says what
// loads it.
//
// Four seeded sessions (run.sh): one whose serve recorded a referer, one whose
// serve recorded none, one whose serve is not in this database at all, and a
// silent rebind -- a session of one row, which records the referer itself.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const SERVED = 'uiref.served.0001aaaa';
const DIRECT = 'uiref.direct.0002bbbb';
const NOHEAD = 'uiref.nohead.0003cccc';
const REBIND = 'uiref.rebind.0004dddd';
const REBIND_FROM = 'https://github.com/unmask-sh/unmask';
const FROM = 'https://www.example.com/search?q=unmask&hl=ja';
const PASSES = 'bv_pow_only,bv_captcha_only,bv_pow_then_captcha,bv_rebind';

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
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(e.message));
  // Every lookup the page makes, so "hover never fetches" and "a second click
  // does not fetch again" are counted rather than assumed.
  const lookups = [];
  page.on('request', r => { if (r.url().includes('/admin/hunt/ja4chain')) lookups.push(r.url()); });

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // ---- helpers -----------------------------------------------------------
  // The referer as a popover states it: which state, and the text shown.
  const readHover = () => page.evaluate(() => {
    const p = document.getElementById('cell-popover');
    if (!p || getComputedStyle(p).display === 'none') return null;
    const el = p.querySelector('[data-referer-state]');
    return el ? { state: el.getAttribute('data-referer-state'), text: el.textContent.trim() } : { state: null };
  });
  const readPinned = () => page.evaluate(() => {
    const clones = document.querySelectorAll('.popover-clone');
    const c = clones[clones.length - 1];
    if (!c) return null;
    const el = c.querySelector('[data-referer-state]');
    return {
      state: el ? el.getAttribute('data-referer-state') : null,
      text: el ? el.textContent.trim() : '',
      value: el && el.querySelector('.session-referer-v, .session-referer-none')
        ? el.querySelector('.session-referer-v, .session-referer-none').textContent.trim() : '',
      phases: Array.from(c.querySelectorAll('.session-timeline .phase-pill')).map(x => x.textContent.trim()),
    };
  });
  const rowAttrs = (bt) => page.evaluate((bt) => {
    const tr = Array.from(document.querySelectorAll('table.events tbody tr'))
      .find(r => r.getAttribute('data-bt') === bt && r.style.display !== 'none');
    return tr ? { referer: tr.getAttribute('data-referer') || '', head: tr.getAttribute('data-head') || '' } : null;
  }, bt);
  // Center of a trigger inside the visible row of a session, scrolled into view.
  const target = (bt, sel) => page.evaluate((bt, sel) => {
    const tr = Array.from(document.querySelectorAll('table.events tbody tr'))
      .find(r => r.getAttribute('data-bt') === bt && r.style.display !== 'none');
    if (!tr) return null;
    const el = tr.querySelector(sel);
    if (!el) return null;
    el.scrollIntoView({ block: 'center' });
    const r = el.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  }, bt, sel);
  const away = async () => { await page.mouse.move(4, 4); await sleep(450); };
  const closePins = async () => {
    for (let i = 0; i < 4; i++) { await page.keyboard.press('Escape'); await sleep(80); }
    await away();
  };
  const PILL = 'td:nth-child(5) .phase-pill';
  const CHAIN = 'td:nth-child(5) .session-chain';
  const DATE = 'td.at time.js-datetime';
  const hover = async (bt, sel) => {
    const t = await target(bt, sel);
    if (!t) return null;
    await page.mouse.move(t.x, t.y);
    await sleep(600);
    const got = await readHover();
    await away();
    return got || { state: 'no popover' };
  };
  const click = async (bt, sel) => {
    const t = await target(bt, sel);
    if (!t) return null;
    await page.mouse.move(t.x, t.y);
    await sleep(100);
    await page.mouse.click(t.x, t.y);
    await sleep(900); // the click may fetch the recorded session first
    const got = await readPinned();
    return got || { state: 'no pinned popover' };
  };

  // ---- 1. the view filtered to the passes --------------------------------
  let resp = await page.goto(BASE + '/admin/hunt/?range=24h&phase=' + encodeURIComponent(PASSES),
    { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `filtered hunt status ${resp.status()}`);

  const before = await rowAttrs(SERVED);
  if (!before) {
    ok(false, 'the seeded pass row is not in the filtered view -- run.sh seeding changed');
  } else {
    ok(before.referer === '' && before.head === '',
      `precondition: the pass row already carries a referer state (${JSON.stringify(before)}) -- ` +
      'the filter stopped excluding the serve, and this test no longer covers the filtered shape');

    // Before anybody looked: neither popover may claim the visitor sent none.
    const d0 = await hover(SERVED, DATE);
    ok(d0 && d0.state === 'unloaded',
      `date popover before the click: state ${JSON.stringify(d0)}, want "unloaded" (it must not say "-")`);
    const p0 = await hover(SERVED, PILL);
    ok(p0 && p0.state === 'unloaded',
      `phase popover on hover: state ${JSON.stringify(p0)}, want "unloaded"`);
    ok(lookups.length === 0, `hovering fetched ${lookups.length} time(s); only a click may`);

    // The click: the recorded session, and where it came from.
    const p1 = await click(SERVED, PILL);
    ok(p1 && p1.state === 'url', `phase popover after the click: state ${JSON.stringify(p1)}, want "url"`);
    ok(p1 && p1.value === FROM,
      `referer shown as ${JSON.stringify(p1 && p1.value)}, want ${JSON.stringify(FROM)} ` +
      '(the stored form escapes "&"; the operator must get the character)');
    ok(p1 && p1.phases.join('>') === 'serve>load>bv_pow_only',
      `timeline phases ${JSON.stringify(p1 && p1.phases)}, want the whole recorded session`);
    ok(lookups.length === 1, `one click made ${lookups.length} lookups, want 1`);
    const after = await rowAttrs(SERVED);
    ok(after && after.referer === FROM && after.head === 'loaded',
      `row state after the click ${JSON.stringify(after)}, want the referer written back`);

    // The date popover now shows what the click found.
    await closePins();
    const d1 = await hover(SERVED, DATE);
    ok(d1 && d1.state === 'url' && d1.text.indexOf(FROM) >= 0,
      `date popover after the click: ${JSON.stringify(d1)}, want the same referer`);

    // Pin and unpin again: the session was already read, so no second lookup.
    await click(SERVED, PILL);
    await closePins();
    ok(lookups.length === 1, `re-opening the same session made ${lookups.length} lookups in total, want 1`);
  }

  // A serve that recorded no referer: "-" is then the truth, and only then.
  if (await rowAttrs(DIRECT)) {
    const p = await click(DIRECT, PILL);
    ok(p && p.state === 'sent' && p.value === '-',
      `session whose serve recorded no referer: ${JSON.stringify(p)}, want state "sent" and "-"`);
    await closePins();
    const d = await hover(DIRECT, DATE);
    ok(d && d.state === 'sent', `its date popover: ${JSON.stringify(d)}, want "sent"`);
  } else {
    ok(false, 'the seeded no-referer session is not in the filtered view');
  }

  // A pass whose serve is not on record here (on a fleet: it landed on another
  // node).  Looked for and not found is its own answer: not "-", and not "not
  // loaded" either.
  if (await rowAttrs(NOHEAD)) {
    const d0 = await hover(NOHEAD, DATE);
    ok(d0 && d0.state === 'unloaded', `serve-less pass before the click: ${JSON.stringify(d0)}, want "unloaded"`);
    const p = await click(NOHEAD, PILL);
    ok(p && p.state === 'nohead', `serve-less pass after the click: ${JSON.stringify(p)}, want "nohead"`);
    ok(p && p.value !== '-' && p.value.length > 3,
      `serve-less pass shows ${JSON.stringify(p && p.value)}; it must say the serve is not on record`);
    await closePins();
    const d1 = await hover(NOHEAD, DATE);
    ok(d1 && d1.state === 'nohead', `its date popover after the click: ${JSON.stringify(d1)}, want "nohead"`);
  } else {
    ok(false, 'the seeded serve-less pass is not in the filtered view');
  }

  // A silent rebind recorded its own referer, so there is nothing to load: the
  // date popover has it before any click.
  if (await rowAttrs(REBIND)) {
    const before = lookups.length;
    const d = await hover(REBIND, DATE);
    ok(d && d.state === 'url' && d.text.indexOf(REBIND_FROM) >= 0,
      `rebind row's date popover: ${JSON.stringify(d)}, want its own referer without a click`);
    const p = await hover(REBIND, PILL);
    ok(p && p.state === 'url', `rebind row's phase popover on hover: ${JSON.stringify(p)}, want "url"`);
    ok(lookups.length === before, 'reading a rebind row\'s referer fetched; the row carries it');
  } else {
    ok(false, 'the seeded rebind row is not in the filtered view');
  }

  // ---- 2. the unfiltered view --------------------------------------------
  // The serve is on the page, so the session knows its referer without asking.
  // Narrowed to the session's address: the log is long, and which page a row
  // lands on is not what this is about.
  const n = lookups.length;
  resp = await page.goto(BASE + '/admin/hunt/?range=24h&ip=127.0.0.21', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `hunt status ${resp.status()}`);
  const whole = await rowAttrs(SERVED);
  ok(whole && whole.referer === FROM && whole.head === 'page',
    `collapsed session state ${JSON.stringify(whole)}, want the referer promoted and head "page"`);
  const c0 = await hover(SERVED, CHAIN);
  ok(c0 && c0.state === 'url', `collapsed chain on hover: ${JSON.stringify(c0)}, want "url"`);
  const c1 = await click(SERVED, CHAIN);
  ok(c1 && c1.state === 'url' && c1.value === FROM, `collapsed chain pinned: ${JSON.stringify(c1)}`);
  await closePins();
  const dw = await hover(SERVED, DATE);
  ok(dw && dw.state === 'url' && dw.text.indexOf(FROM) >= 0,
    `date popover of the collapsed session: ${JSON.stringify(dw)}, want the referer`);

  resp = await page.goto(BASE + '/admin/hunt/?range=24h&ip=127.0.0.22', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `hunt status ${resp.status()}`);
  const dn = await rowAttrs(DIRECT);
  ok(dn && dn.referer === '' && dn.head === 'page', `no-referer session state ${JSON.stringify(dn)}`);
  const c2 = await hover(DIRECT, CHAIN);
  ok(c2 && c2.state === 'sent', `no-referer session on hover: ${JSON.stringify(c2)}, want "sent"`);
  const c3 = await click(DIRECT, CHAIN);
  ok(c3 && c3.state === 'sent' && c3.value === '-', `no-referer session pinned: ${JSON.stringify(c3)}`);
  await closePins();
  ok(lookups.length === n,
    `the unfiltered view made ${lookups.length - n} lookups; with the serve on the page there is nothing to fetch`);

  ok(jsErrors.length === 0, 'page errors: ' + jsErrors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('referer-on-click: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
