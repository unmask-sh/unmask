// viewer-nav: the top nav offers an account the pages its role can open.
//
// A viewer gets the dashboard, the statistics and bot hunt -- BAN management
// and the settings refuse the role, and an entry that answers "forbidden" is
// not offered (partial_nav.html).  The dashboard's shortcut tiles to those
// two pages are not drawn for it either, nor the user menu's audit log.  Bot
// hunt opens for it as a reading: the rankings and the event log without the
// BAN and rule buttons, whose action route takes admin.  The pages behind
// the missing entries still refuse the role: the settings page answers 403
// to a viewer since 0.1.52.  An administrator gets the five entries and the
// six tiles.
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
  ok(nav.length === 3, 'viewer: nav entries ' + JSON.stringify(nav));
  ok(nav[0] && nav[0].text === 'ダッシュボード' && nav[0].active, 'viewer: first entry ' + JSON.stringify(nav[0]));
  ok(nav[1] && nav[1].text === '統計' && /\/admin\/stats\/$/.test(nav[1].href), 'viewer: second entry ' + JSON.stringify(nav[1]));
  ok(nav[2] && nav[2].text === 'bot ハント' && /\/admin\/hunt\/$/.test(nav[2].href), 'viewer: third entry ' + JSON.stringify(nav[2]));
  ok(!nav.some(e => /\/admin\/(bans|settings)\//.test(e.href)), 'viewer: an entry to a page the role cannot open: ' + JSON.stringify(nav));
  const tiles = await tilesOf(vw);
  ok(tiles.length === 4 && tiles[0] === '統計' && tiles[1] === 'bot ハント' && /^共有 BAN/.test(tiles[2]) && /^ドキュメント/.test(tiles[3]), 'viewer: tiles ' + JSON.stringify(tiles));
  // The dashboard's own links to admin pages are not drawn either: the BAN
  // tile's "view list" and the reasons' gears.  The reasons' records in bot
  // hunt and the "browse all events" line under them stay: bot hunt reads.
  const inPage = await vw.evaluate(() => ({
    bansLink: !!document.querySelector('.kpi .sub a[href$="/admin/bans/"], a[href$="/admin/bans/"]:not(nav a)'),
    huntLinks: Array.from(document.querySelectorAll('a[href*="/admin/hunt/"]')).filter(a => !a.closest('nav')).length,
    gears: document.querySelectorAll('a.rs-set').length,
    settingsLinks: Array.from(document.querySelectorAll('a[href*="/admin/settings/"]')).filter(a => !a.closest('nav')).length,
    reasonsDesc: (document.querySelector('.rs-desc') || {}).textContent || '',
  }));
  ok(!inPage.bansLink && inPage.huntLinks >= 1 && inPage.gears === 0 && inPage.settingsLinks === 0, 'viewer: in-page links to admin pages ' + JSON.stringify(inPage));
  ok(/bot ハント/.test(inPage.reasonsDesc) && !/⚙/.test(inPage.reasonsDesc), 'viewer: the reasons text should tell of bot hunt and not of the gear: ' + inPage.reasonsDesc);
  // The user menu: the profile and logout, no audit log.
  const menu = await vw.evaluate(() => Array.from(document.querySelectorAll('.user-menu-pop a')).map(a => new URL(a.href).pathname));
  ok(menu.length === 1 && /\/admin\/profile\/$/.test(menu[0]), 'viewer: user menu ' + JSON.stringify(menu));
  if (SHOTS) {
    try { await vw.screenshot({ path: path.join(SHOTS, 'viewer-nav.png'), clip: { x: 0, y: 0, width: 1400, height: 60 } }); } catch (e) {}
    try { await vw.screenshot({ path: path.join(SHOTS, 'viewer-dashboard.png'), fullPage: true }); } catch (e) {}
  }
  // The pages behind the missing entries refuse the role; the offered ones open.
  for (const [p, want] of [['/admin/settings/', 403], ['/admin/settings/rate-limit/', 403], ['/admin/bans/', 403],
    ['/admin/stats/', 200], ['/admin/live/', 200], ['/admin/hunt/', 200], ['/admin/hunt/ja4chain?bt=x&ts=0', 400] /* the lookup refuses the token, not the role */, ['/admin/community-bans/', 200], ['/admin/profile/', 200]]) {
    const got = await statusOf(vw, p);
    ok(got === want, `viewer: ${p} answers ${got}, want ${want}`);
  }
  // The live view keeps its "browse all events" link to bot hunt.
  await vw.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  nav = await navOf(vw);
  ok(nav.length === 3 && nav[0].active, 'viewer on live: the dashboard entry is marked: ' + JSON.stringify(nav));
  ok((await vw.evaluate(() => Array.from(document.querySelectorAll('a[href*="/admin/hunt/"]')).filter(a => !a.closest('nav')).length)) === 1, 'viewer on live: the link to bot hunt');
  // Bot hunt itself: the entry is marked, the page reads, and nothing on it
  // posts to the action route -- no BAN or rule button on the rankings, no
  // actions column in the event log, no way to a custom rule.
  await vw.goto(BASE + '/admin/hunt/', { waitUntil: 'networkidle2' });
  nav = await navOf(vw);
  ok(nav.length === 3 && nav[2].active && nav.filter(e => e.active).length === 1, 'viewer on hunt: the hunt entry is marked: ' + JSON.stringify(nav));
  const huntPage = await vw.evaluate(() => ({
    forms: document.querySelectorAll('form[action$="/admin/hunt/action"]').length,
    rankButtons: document.querySelectorAll('.js-ban-form, .js-asn-form, .js-ua-form').length,
    customRule: document.querySelectorAll('a.cr-from-filter').length,
    actionsCol: document.querySelectorAll('th[style="width:4rem"]').length, // the event log's column (the rankings' own cells keep their pills)
    settingsLinks: Array.from(document.querySelectorAll('a[href*="/admin/settings/"]')).filter(a => !a.closest('nav')).length,
    table: !!document.querySelector('table'),
  }));
  ok(huntPage.table && huntPage.forms === 0 && huntPage.rankButtons === 0 && huntPage.customRule === 0 && huntPage.actionsCol === 0, 'viewer on hunt: ' + JSON.stringify(huntPage));
  // The mark follows the page: the statistics' entry on the statistics.
  await vw.goto(BASE + '/admin/stats/', { waitUntil: 'networkidle2' });
  nav = await navOf(vw);
  ok(nav.length === 3 && nav[1].active && !nav[0].active, 'viewer on stats: ' + JSON.stringify(nav));
  // The community feed: the tab strip has the feed alone, the admin tabs are not drawn.
  await vw.goto(BASE + '/admin/community-bans/', { waitUntil: 'networkidle2' });
  const tabs = await vw.evaluate(() => Array.from(document.querySelectorAll('nav.ban-tabs a')).map(a => new URL(a.href).pathname));
  ok(tabs.length === 1 && /\/admin\/community-bans\/$/.test(tabs[0]), 'viewer: ban tabs ' + JSON.stringify(tabs));
  nav = await navOf(vw);
  ok(nav.length === 3 && !nav.some(e => e.active), 'viewer on the community feed: no entry is marked: ' + JSON.stringify(nav));
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
  ok(suPage.bansLink && suPage.huntLinks >= 1 && /bot ハント/.test(suPage.reasonsDesc) && /⚙/.test(suPage.reasonsDesc), 'admin: in-page links ' + JSON.stringify(suPage));
  // On bot hunt the administrator keeps the event log's actions column (the
  // rankings' buttons need rows, which a fresh instance has none of).
  await su.goto(BASE + '/admin/hunt/', { waitUntil: 'networkidle2' });
  ok((await su.evaluate(() => document.querySelectorAll('th[style="width:4rem"]').length)) === 1, 'admin on hunt: the actions column');
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
