// viewer-nav: the top nav offers an account the pages its role can open.
//
// A viewer gets the dashboard and the statistics -- bot hunt, BAN management
// and the settings refuse the role, and an entry that answers "forbidden" is
// not offered (partial_nav.html).  The dashboard's shortcut tiles to those
// three pages are not drawn for it either, nor the user menu's audit log.
// The pages themselves still refuse the role: the settings page answers 403
// to a viewer since 0.1.52, as bot hunt always has.  An administrator gets
// the five entries and the six tiles.
//
// The account is created here with the CLI, against the runner's config.
const puppeteer = require('puppeteer-core');
const path = require('path');
const { execFileSync } = require('child_process');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CFG = process.env.UI_E2E_CONFIG || '';
const BIN = process.env.UNMASK_BIN || path.join(process.env.UI_E2E_OUT || '', '..', 'unmask');
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';
const VIEWER = 'ui-viewer';
const VPASS = 'Viewer-ui-e2e-' + Math.random().toString(36).slice(2, 10) + 'Aa1';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

async function login(browser, username, password, lang) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.errors = [];
  page.on('pageerror', e => page.errors.push(e.message));
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.evaluate(l => { document.cookie = 'unmask_locale=' + l + '; path=/'; }, lang);
  await page.type('input[name="username"]', username);
  await page.type('input[name="password"]', password);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
  ok(/\/admin\/?$/.test(page.url()), `${username}: login landed on ${page.url()}`);
  return page;
}

const navOf = page => page.evaluate(() => Array.from(document.querySelectorAll('nav.nav a')).map(a => ({
  text: a.textContent.trim().replace(/\s+\(\d+\)$/, ''), href: new URL(a.href).pathname, active: a.classList.contains('active'),
})));
const tilesOf = page => page.evaluate(() => Array.from(document.querySelectorAll('a.shortcut .ttl')).map(e => e.textContent.trim()));
const statusOf = (page, p) => page.evaluate(async u => (await fetch(u, { credentials: 'same-origin', cache: 'no-store' })).status, BASE + p);

(async () => {
  execFileSync(BIN, ['user', 'create', VIEWER, '-role', 'viewer', '-password', VPASS, '-config', CFG],
    { env: Object.assign({}, process.env, { UNMASK_NO_PRIVDROP: '1' }), stdio: 'pipe' });

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
  });

  // ---- the viewer -----------------------------------------------------------
  const vw = await login(browser, VIEWER, VPASS, 'ja');
  let nav = await navOf(vw);
  ok(nav.length === 2, 'viewer: nav entries ' + JSON.stringify(nav));
  ok(nav[0] && nav[0].text === 'ダッシュボード' && nav[0].active, 'viewer: first entry ' + JSON.stringify(nav[0]));
  ok(nav[1] && nav[1].text === '統計' && /\/admin\/stats\/$/.test(nav[1].href), 'viewer: second entry ' + JSON.stringify(nav[1]));
  ok(!nav.some(e => /\/admin\/(hunt|bans|settings)\//.test(e.href)), 'viewer: an entry to a page the role cannot open: ' + JSON.stringify(nav));
  const tiles = await tilesOf(vw);
  ok(tiles.length === 3 && tiles[0] === '統計' && /^共有 BAN/.test(tiles[1]) && /^ドキュメント/.test(tiles[2]), 'viewer: tiles ' + JSON.stringify(tiles));
  // The dashboard's own links to admin pages are not drawn either: the BAN
  // tile's "view list", the reasons' records in bot hunt and their gears, the
  // "browse all events" line under them.
  const inPage = await vw.evaluate(() => ({
    bansLink: !!document.querySelector('.kpi .sub a[href$="/admin/bans/"], a[href$="/admin/bans/"]:not(nav a)'),
    huntLinks: Array.from(document.querySelectorAll('a[href*="/admin/hunt/"]')).filter(a => !a.closest('nav')).length,
    gears: document.querySelectorAll('a.rs-set').length,
    settingsLinks: Array.from(document.querySelectorAll('a[href*="/admin/settings/"]')).filter(a => !a.closest('nav')).length,
    reasonsDesc: (document.querySelector('.rs-desc') || {}).textContent || '',
  }));
  ok(!inPage.bansLink && inPage.huntLinks === 0 && inPage.gears === 0 && inPage.settingsLinks === 0, 'viewer: in-page links to admin pages ' + JSON.stringify(inPage));
  ok(inPage.reasonsDesc === '' || !/bot ハント/.test(inPage.reasonsDesc), 'viewer: the reasons text still tells of the links: ' + inPage.reasonsDesc);
  // The user menu: the profile and logout, no audit log.
  const menu = await vw.evaluate(() => Array.from(document.querySelectorAll('.user-menu-pop a')).map(a => new URL(a.href).pathname));
  ok(menu.length === 1 && /\/admin\/profile\/$/.test(menu[0]), 'viewer: user menu ' + JSON.stringify(menu));
  if (SHOTS) {
    try { await vw.screenshot({ path: path.join(SHOTS, 'viewer-nav.png'), clip: { x: 0, y: 0, width: 1400, height: 60 } }); } catch (e) {}
    try { await vw.screenshot({ path: path.join(SHOTS, 'viewer-dashboard.png'), fullPage: true }); } catch (e) {}
  }
  // The pages behind the missing entries refuse the role; the offered ones open.
  for (const [p, want] of [['/admin/settings/', 403], ['/admin/settings/rate-limit/', 403], ['/admin/hunt/', 403], ['/admin/bans/', 403],
    ['/admin/stats/', 200], ['/admin/live/', 200], ['/admin/community-bans/', 200], ['/admin/profile/', 200]]) {
    const got = await statusOf(vw, p);
    ok(got === want, `viewer: ${p} answers ${got}, want ${want}`);
  }
  // The live view: no "browse all events" link to bot hunt for a viewer.
  await vw.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  nav = await navOf(vw);
  ok(nav.length === 2 && nav[0].active, 'viewer on live: the dashboard entry is marked: ' + JSON.stringify(nav));
  ok((await vw.evaluate(() => Array.from(document.querySelectorAll('a[href*="/admin/hunt/"]')).filter(a => !a.closest('nav')).length)) === 0, 'viewer on live: a link to bot hunt');
  // The mark follows the page: the statistics' entry on the statistics.
  await vw.goto(BASE + '/admin/stats/', { waitUntil: 'networkidle2' });
  nav = await navOf(vw);
  ok(nav.length === 2 && nav[1].active && !nav[0].active, 'viewer on stats: ' + JSON.stringify(nav));
  // The community feed: the tab strip has the feed alone, the admin tabs are not drawn.
  await vw.goto(BASE + '/admin/community-bans/', { waitUntil: 'networkidle2' });
  const tabs = await vw.evaluate(() => Array.from(document.querySelectorAll('nav.ban-tabs a')).map(a => new URL(a.href).pathname));
  ok(tabs.length === 1 && /\/admin\/community-bans\/$/.test(tabs[0]), 'viewer: ban tabs ' + JSON.stringify(tabs));
  nav = await navOf(vw);
  ok(nav.length === 2 && !nav.some(e => e.active), 'viewer on the community feed: no entry is marked: ' + JSON.stringify(nav));
  ok(vw.errors.length === 0, 'viewer: page errors ' + vw.errors.join(' | '));

  // ---- the administrator ----------------------------------------------------
  const su = await login(browser, USER, PASS, 'ja');
  nav = await navOf(su);
  ok(nav.length === 5 && nav.map(e => e.text).join(',') === 'ダッシュボード,統計,bot ハント,BAN 管理,設定', 'admin: nav ' + JSON.stringify(nav));
  ok(nav[0].active && nav.filter(e => e.active).length === 1, 'admin: the dashboard is marked: ' + JSON.stringify(nav));
  ok((await tilesOf(su)).length === 6, 'admin: tiles ' + JSON.stringify(await tilesOf(su)));
  ok((await statusOf(su, '/admin/settings/')) === 200, 'admin: the settings page does not open');
  const suPage = await su.evaluate(() => ({
    bansLink: !!document.querySelector('a[href$="/admin/bans/"]:not(nav a)'),
    huntLinks: Array.from(document.querySelectorAll('a[href*="/admin/hunt/"]')).filter(a => !a.closest('nav')).length,
    reasonsDesc: (document.querySelector('.rs-desc') || {}).textContent || '',
  }));
  ok(suPage.bansLink && suPage.huntLinks >= 1 && /bot ハント/.test(suPage.reasonsDesc), 'admin: in-page links ' + JSON.stringify(suPage));
  await su.goto(BASE + '/admin/advisor/', { waitUntil: 'networkidle2' });
  nav = await navOf(su);
  ok(nav.filter(e => e.active).length === 1 && /\/admin\/bans\/$/.test(nav.find(e => e.active).href), 'admin on the advisor: the BAN entry is marked: ' + JSON.stringify(nav));
  ok(su.errors.length === 0, 'admin: page errors ' + su.errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.log('FAIL viewer-nav:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok viewer-nav');
})().catch(e => { console.log('FAIL viewer-nav: ' + (e.stack || e)); process.exit(1); });
