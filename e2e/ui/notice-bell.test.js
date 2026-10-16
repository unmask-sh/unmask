// The notification bell in the top bar: an administrator sees how many
// alerts they have not opened the list to, the panel under the bell lists
// them in the reader's language and clears the count, and the page behind
// it lists everything.  The alerts are seeded as the notifier writes them
// (the notice package's rows), since a real ban or burst would need traffic.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, UI_E2E_OUT (the work dir's
// out/, beside which run.sh keeps data/unmask.sqlite), CHROME_BIN,
// UI_E2E_SHOT_DIR.
const puppeteer = require('puppeteer-core');
const path = require('path');
const { spawnSync } = require('child_process');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const DB = path.join(path.dirname(process.env.UI_E2E_OUT || '/tmp/x/out'), 'data', 'unmask.sqlite');
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Three rows, as the daemon writes them: an hour of bans folded into one,
// a burst, the over-block breaker tripping.
function seed() {
  const py = `
import json, sqlite3, sys, time
c = sqlite3.connect(sys.argv[1], timeout=10)
now = int(time.time())
rows = [
  (now - 3000, now - 120, "ban_created", "info", "", "ban_created:%d" % ((now - 3000) // 3600 * 3600), 14,
   {"ip": "203.0.113.77", "ja4": "t13d1516h2_8daaf6152771_02713d6af862", "source": "honeypot",
    "reason": "wp-login: https://ui-e2e.example/wp-login.php", "banned_by": "",
    "sources": {"honeypot": 12, "manual": 2}, "ips": ["203.0.113.77", "203.0.113.78", "203.0.113.79"]}),
  (now - 600, now - 600, "challenge_burst", "warn", "", "", 1, {"count_per_5m": 84, "threshold": 50}),
  (now - 60, now - 60, "over_block", "crit", "", "", 1,
   {"tripped": True, "window_minutes": 10, "stuck": 7, "ran_challenge": 9, "stuck_percent": 77,
    "rechallenged": 5, "verify_failed": 2, "auto_passthrough": False, "min_stuck": 3, "min_percent": 50}),
]
for created, updated, kind, sev, site, gk, n, detail in rows:
    c.execute("INSERT INTO unmask_notice (created_at, updated_at, kind, severity, user_id, site, group_key, events, detail) VALUES (?,?,?,?,NULL,?,?,?,?)",
              (created, updated, kind, sev, site, gk, n, json.dumps(detail, separators=(",", ":"))))
c.commit()
`;
  const r = spawnSync('python3', ['-I', '-c', py, DB], { encoding: 'utf8' });
  return r.status === 0 ? '' : (r.stderr || 'python failed');
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // The page's language: the bell's lines are written in it.
  await page.evaluate(() => { document.cookie = 'unmask_locale=ja; path=/'; });

  const before = await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  ok(before.status() === 200, `/admin/ status ${before.status()}`);
  const unreadBefore = await page.evaluate(() => {
    const b = document.getElementById('nbell-badge');
    return document.getElementById('nbell') ? (b ? parseInt(b.textContent, 10) : 0) : -1;
  });
  ok(unreadBefore >= 0, 'the bell is not in the top bar');

  const seedErr = seed();
  ok(seedErr === '', 'seeding notices failed: ' + seedErr);

  await page.reload({ waitUntil: 'networkidle2' });
  const lit = await page.evaluate(() => {
    const bell = document.getElementById('nbell');
    const b = document.getElementById('nbell-badge');
    const menu = document.getElementById('user-menu');
    return {
      badge: b ? b.textContent.trim() : null,
      // the bell stands left of the account menu
      leftOfMenu: bell && menu ? bell.getBoundingClientRect().right <= menu.getBoundingClientRect().left : false,
      inBar: bell ? !!bell.closest('header.unmask-header') : false,
    };
  });
  ok(lit.badge === String(unreadBefore + 3), 'the badge is not the three new alerts: ' + lit.badge);
  ok(lit.leftOfMenu, 'the bell is not left of the account menu');
  ok(lit.inBar, 'the bell is not in the top bar');
  if (SHOTS) {
    try { await page.screenshot({ path: path.join(SHOTS, 'notice-bell-closed.png'), clip: { x: 700, y: 0, width: 700, height: 60 } }); } catch (e) {}
  }

  // Open the panel: the rows, in Japanese, newest first; the badge goes.
  await page.click('#nbell-btn');
  await page.waitForSelector('#nbell-list .nbell-item', { timeout: 5000 }).catch(() => {});
  await sleep(300);
  const panel = await page.evaluate(() => {
    const items = Array.from(document.querySelectorAll('#nbell-list .nbell-item'));
    return {
      n: items.length,
      kinds: items.map(i => i.dataset.kind),
      titles: items.map(i => (i.querySelector('.nbell-title') || {}).textContent || ''),
      bodies: items.map(i => (i.querySelector('.nbell-body') || {}).textContent || ''),
      times: items.map(i => (i.querySelector('time') || {}).textContent || ''),
      sev: items.map(i => i.className),
      open: document.getElementById('nbell').classList.contains('open'),
      badge: !!document.getElementById('nbell-badge'),
      allLink: (document.querySelector('#nbell-pop .nbell-head a') || {}).getAttribute ? document.querySelector('#nbell-pop .nbell-head a').getAttribute('href') : '',
    };
  });
  ok(panel.open, 'the panel did not open');
  ok(panel.n >= 3, 'the panel lists ' + panel.n + ' rows, want the 3 seeded');
  ok(panel.kinds.slice(0, 3).join(',') === 'over_block,challenge_burst,ban_created', 'rows are not newest first: ' + panel.kinds.join(','));
  ok(/challenge を通れない訪問者がいる可能性があります/.test(panel.titles[0]), 'over-block title not in Japanese: ' + panel.titles[0]);
  ok(/5 分間に challenge 84 回/.test(panel.titles[1]), 'burst title: ' + panel.titles[1]);
  ok(/BAN 14 件/.test(panel.titles[2]), 'folded ban title: ' + panel.titles[2]);
  ok(/honeypot 12 \/ manual 2 · 最新 203\.0\.113\.77/.test(panel.bodies[2]), 'folded ban body: ' + panel.bodies[2]);
  ok(/sev-crit/.test(panel.sev[0]) && /sev-warn/.test(panel.sev[1]) && /sev-info/.test(panel.sev[2]), 'severity classes: ' + panel.sev.join(' | '));
  // The page's script formats the time in the operator's zone (slash date, 24h).
  ok(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/.test(panel.times[0]), 'the panel time is not formatted by the page: ' + panel.times[0]);
  ok(!panel.badge, 'the badge is still there with the panel open');
  ok(panel.allLink === '/unmask/admin/notices/', 'the "show all" link: ' + panel.allLink);
  if (SHOTS) {
    try { await page.screenshot({ path: path.join(SHOTS, 'notice-bell-open.png'), clip: { x: 700, y: 0, width: 700, height: 420 } }); } catch (e) {}
  }

  // Closed by a click outside; nothing new after a reload.
  await page.mouse.click(300, 500);
  const closed = await page.evaluate(() => !document.getElementById('nbell').classList.contains('open'));
  ok(closed, 'a click outside did not close the panel');
  await page.reload({ waitUntil: 'networkidle2' });
  const afterBadge = await page.evaluate(() => !!document.getElementById('nbell-badge'));
  ok(!afterBadge, 'the badge is back after the list was opened');

  // The page: every row, the kind filter, and the retention line.
  const list = await page.goto(BASE + '/admin/notices/', { waitUntil: 'networkidle2' });
  ok(list.status() === 200, `/admin/notices/ status ${list.status()}`);
  const pageInfo = await page.evaluate(() => ({
    rows: document.querySelectorAll('table.notices tbody tr').length,
    h1: (document.querySelector('h1') || {}).textContent,
    filters: Array.from(document.querySelectorAll('.kinds a')).map(a => a.textContent),
    meta: (document.querySelector('p.meta') || {}).textContent || '',
    newTags: document.querySelectorAll('.ntag-new').length,
  }));
  ok(pageInfo.rows >= 3, 'the page lists ' + pageInfo.rows + ' rows');
  ok(pageInfo.h1 === '通知', 'the page title: ' + pageInfo.h1);
  ok(pageInfo.filters.length === 5 && pageInfo.filters[0] === 'すべて', 'the kind filter: ' + pageInfo.filters.join(','));
  ok(/ログ管理/.test(pageInfo.meta), 'the retention line is missing');
  ok(pageInfo.newTags === 0, 'rows read from the panel are marked new on the page: ' + pageInfo.newTags);
  if (SHOTS) {
    try { await page.screenshot({ path: path.join(SHOTS, 'notices-page.png'), fullPage: true }); } catch (e) {}
  }
  const filtered = await page.goto(BASE + '/admin/notices/?kind=over_block', { waitUntil: 'networkidle2' });
  ok(filtered.status() === 200, 'filtered status ' + filtered.status());
  const onlyKinds = await page.evaluate(() => Array.from(document.querySelectorAll('table.notices tbody tr')).map(tr => tr.dataset.kind));
  ok(onlyKinds.length >= 1 && onlyKinds.every(k => k === 'over_block'), 'the kind filter did not narrow: ' + onlyKinds.join(','));

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.log('FAIL notice-bell:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok notice-bell');
})().catch(e => { console.log('FAIL notice-bell: ' + (e.stack || e)); process.exit(1); });
