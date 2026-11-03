// user-menu-keyboard: the account menu opens, walks and closes from the keyboard.
//
// The menu at the right end of the top bar holds the profile, the user and
// audit pages for an administrator, and the logout.  Through 0.1.53 its
// trigger was a <span> in a focusable <div>: the Tab key reached it, drew
// no ring, and Enter and Space did nothing -- a keyboard user could not
// open it, so could not log out.  The trigger is a <button> now
// (partial_user_menu.html): Enter and Space toggle it, the down arrow opens
// it on the first entry, the arrows walk the entries and wrap, Escape
// closes it and puts the focus back on the trigger, Tab out of the last
// entry closes it, and Enter on the logout entry logs out.
//
// The account is created here with the CLI, since logging out ends every
// session of the account.
const puppeteer = require('puppeteer-core');
const path = require('path');
const { execFileSync } = require('child_process');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CFG = process.env.UI_E2E_CONFIG || '';
const BIN = process.env.UNMASK_BIN || path.join(process.env.UI_E2E_OUT || '', '..', 'unmask');
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';
const NAME = 'ui-menu';
const PASS = 'Menu-ui-e2e-' + Math.random().toString(36).slice(2, 10) + 'Aa1';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  execFileSync(BIN, ['user', 'create', NAME, '-role', 'admin', '-password', PASS, '-config', CFG],
    { env: Object.assign({}, process.env, { UNMASK_NO_PRIVDROP: '1' }), stdio: 'pipe' });

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();
  page.errors = [];
  page.on('pageerror', e => page.errors.push(e.message));
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.evaluate(() => { document.cookie = 'unmask_locale=ja; path=/'; });
  await page.type('input[name="username"]', NAME);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
  ok(/\/admin\/?$/.test(page.url()), 'login landed on ' + page.url());

  // What the menu looks like and where the focus is, in one reading.
  const state = () => page.evaluate(() => {
    const m = document.getElementById('user-menu');
    const b = document.getElementById('user-menu-btn');
    const pop = document.getElementById('user-menu-pop');
    const a = document.activeElement;
    return {
      button: !!b && b.tagName === 'BUTTON' && b.getAttribute('aria-haspopup') === 'true' && b.getAttribute('aria-controls') === 'user-menu-pop',
      open: !!m && m.classList.contains('open'),
      expanded: b ? b.getAttribute('aria-expanded') : null,
      visible: !!pop && getComputedStyle(pop).display !== 'none',
      focus: !a ? '' : a.id === 'user-menu-btn' ? 'trigger'
        : a.closest('#user-menu-pop') ? (a.tagName === 'A' ? new URL(a.href).pathname : a.tagName.toLowerCase() + ':' + a.textContent.trim()) : 'outside',
    };
  });
  let s = await state();
  ok(s.button, 'the trigger is a button with the popup attributes: ' + JSON.stringify(s));
  ok(!s.open && s.expanded === 'false' && !s.visible, 'the menu starts closed: ' + JSON.stringify(s));

  // Enter opens, Escape closes and returns the focus to the trigger.
  await page.focus('#user-menu-btn');
  await page.keyboard.press('Enter');
  s = await state();
  ok(s.open && s.expanded === 'true' && s.visible && s.focus === 'trigger', 'Enter opens the menu: ' + JSON.stringify(s));
  if (SHOTS) { try { await page.screenshot({ path: path.join(SHOTS, 'user-menu-keyboard-open.png'), clip: { x: 1000, y: 0, width: 400, height: 260 } }); } catch (e) {} }
  await page.keyboard.press('Escape');
  s = await state();
  ok(!s.open && s.expanded === 'false' && !s.visible && s.focus === 'trigger', 'Escape closes it and keeps the focus on the trigger: ' + JSON.stringify(s));

  // Space opens too; Enter again closes.
  await page.keyboard.press('Space');
  s = await state();
  ok(s.open && s.expanded === 'true', 'Space opens the menu: ' + JSON.stringify(s));
  await page.keyboard.press('Enter');
  s = await state();
  ok(!s.open && s.expanded === 'false', 'Enter on the open menu closes it: ' + JSON.stringify(s));

  // The down arrow opens on the first entry (the profile); the up arrow
  // wraps to the last (the logout); Escape from an entry goes back to the
  // trigger.
  await page.keyboard.press('ArrowDown');
  s = await state();
  ok(s.open && /\/admin\/profile\/$/.test(s.focus), 'the down arrow opens the menu on the profile entry: ' + JSON.stringify(s));
  await page.keyboard.press('ArrowUp');
  s = await state();
  ok(s.open && /^button:/.test(s.focus), 'the up arrow wraps to the logout entry: ' + JSON.stringify(s));
  await page.keyboard.press('ArrowDown');
  s = await state();
  ok(s.open && /\/admin\/profile\/$/.test(s.focus), 'the down arrow wraps back to the profile entry: ' + JSON.stringify(s));
  await page.keyboard.press('Escape');
  s = await state();
  ok(!s.open && s.focus === 'trigger', 'Escape from an entry closes the menu and returns to the trigger: ' + JSON.stringify(s));

  // Tab walks the entries in order and, past the last, closes the menu.
  await page.keyboard.press('Enter');
  const walked = [];
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press('Tab');
    s = await state();
    if (s.focus === 'outside' || s.focus === 'trigger' || s.focus === '') break;
    walked.push(s.focus);
  }
  ok(walked.length >= 3 && /\/admin\/profile\/$/.test(walked[0]) && /\/admin\/audit\/$/.test(walked[walked.length - 2]) && /^button:/.test(walked[walked.length - 1]),
    'Tab walks profile .. audit .. logout for an administrator: ' + JSON.stringify(walked));
  ok(!s.open && s.expanded === 'false', 'Tab past the last entry closes the menu: ' + JSON.stringify(s));

  // A mouse user is not worse off: the click toggles, a click elsewhere closes.
  await page.click('#user-menu-btn');
  s = await state();
  ok(s.open && s.expanded === 'true', 'a click opens the menu: ' + JSON.stringify(s));
  await page.mouse.click(300, 400);
  s = await state();
  ok(!s.open && s.expanded === 'false', 'a click elsewhere closes it: ' + JSON.stringify(s));

  // Logging out from the keyboard alone: open, up to the logout entry, Enter.
  await page.focus('#user-menu-btn');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowUp');
  s = await state();
  ok(/^button:/.test(s.focus), 'the logout entry has the focus: ' + JSON.stringify(s));
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.keyboard.press('Enter'),
  ]);
  ok(/\/admin\/login/.test(page.url()), 'Enter on the logout entry logs out, landing on ' + page.url());
  const stillIn = await page.evaluate(async u => (await fetch(u, { credentials: 'same-origin', cache: 'no-store', redirect: 'manual' })).status, BASE + '/admin/profile/');
  ok(stillIn !== 200, 'after the logout the profile answers ' + stillIn + ', not 200');
  ok(page.errors.length === 0, 'page errors ' + page.errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.log('FAIL user-menu-keyboard:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok user-menu-keyboard');
})().catch(e => { console.log('FAIL user-menu-keyboard: ' + (e.stack || e)); process.exit(1); });
