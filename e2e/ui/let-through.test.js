// BAN > Let through: what the site answered without a challenge, by the
// ground it passed on, with the addresses behind each ground.
//
// What has to hold on the page: the ground a stranger can use is open with
// its addresses, the one nothing shows to have met the challenge first and
// marked; an address on two sites is two rows, each naming its site; "no
// ground found" closes the page and stands out when it holds anything; the
// pass cookie is a count without a list; a long path or a long site name
// does not widen the page; and the BAN button opens the dialog the other BAN
// pages use, naming the address.  And the way in for the ground that should be
// empty: the notification list's row for it (seeded here as the daemon
// writes it) opens the page at that ground.
//
// run.sh seeds the rows (10.9.0.1 - 10.9.0.4, the first of them on two sites).
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
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';
const DB = path.join(path.dirname(process.env.UI_E2E_OUT || '/tmp/x/out'), 'data', 'unmask.sqlite');

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

// The notification list's row of this hour's requests let through on no
// ground, as the daemon writes it (the notice package's row).
function seedNotice() {
  const py = `
import json, sqlite3, sys, time
c = sqlite3.connect(sys.argv[1], timeout=10)
now = int(time.time())
hour = now // 3600 * 3600
c.execute("INSERT INTO unmask_notice (created_at, updated_at, kind, severity, user_id, site, group_key, events, detail) VALUES (?,?,?,?,NULL,?,?,?,?)",
          (now - 90, now - 30, "let_through_fault", "warn", "", "let_through_fault:%d" % hour, 2,
           json.dumps({"hour": hour, "sites": {"default": 2}, "more": 0}, separators=(",", ":"))))
c.commit()
`;
  const r = spawnSync('python3', ['-I', '-c', py, DB], { encoding: 'utf8' });
  return r.status === 0 ? '' : (r.stderr || 'python failed');
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1366, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/let-through/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/let-through/ status ${resp.status()}`);
  if (SHOTS) await page.screenshot({ path: SHOTS + '/let-through.png', fullPage: true });

  const st = await page.evaluate(() => {
    const sec = r => document.querySelector('details.let-sec[data-reason="' + r + '"]');
    const rowsOf = r => Array.from(sec(r) ? sec(r).querySelectorAll('table.let tbody tr') : []);
    const name = rowsOf('name');
    return {
      tabActive: !!document.querySelector('.ban-tabs a.active[href$="/admin/let-through/"]'),
      tabs: document.querySelectorAll('.ban-tabs a').length,
      sections: document.querySelectorAll('details.let-sec').length,
      nameOpen: sec('name') ? sec('name').open : null,
      nameRows: name.map(tr => tr.dataset.ip),
      nameNever: name.map(tr => !!tr.querySelector('.let-mark.never')),
      nameBadge: sec('name') ? !!sec('name').querySelector('summary .let-unchecked') : false,
      nameSites: name.map(tr => { const s = tr.querySelector('td.path .cp-site'); return s ? s.textContent : ''; }),
      siteClip: name.map(tr => { const s = tr.querySelector('td.path .cp-site'); return s ? s.scrollWidth > s.clientWidth + 1 : false; }),
      siteFull: name.map(tr => { const s = tr.querySelector('td.path .cp-site'); return s ? (s.dataset.fullValue || '') : ''; }),
      siteAbovePath: name.map(tr => { const s = tr.querySelector('td.path .cp-site'), p = tr.querySelector('td.path .clamp-v:not(.cp-site)');
        return s && p ? s.getBoundingClientRect().bottom <= p.getBoundingClientRect().top + 1 : false; }),
      pathHead: sec('name') ? (sec('name').querySelectorAll('table.let thead th')[3] || {}).textContent || '' : '',
      faultOpen: sec('none') ? sec('none').open : null,
      faultMarked: sec('none') ? sec('none').classList.contains('fault') && sec('none').classList.contains('has') : false,
      faultRows: rowsOf('none').map(tr => tr.dataset.ip),
      lastReason: (Array.from(document.querySelectorAll('details.let-sec')).pop() || { dataset: {} }).dataset.reason,
      firstReason: (document.querySelector('details.let-sec') || { dataset: {} }).dataset.reason,
      pathOpen: sec('path') ? sec('path').open : null,
      cookieTable: sec('cookie') ? !!sec('cookie').querySelector('table') : null,
      cookieText: sec('cookie') ? sec('cookie').querySelector('summary').textContent : '',
      emptyOpen: sec('watch') ? sec('watch').open : null,
      pageScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      times: Array.from(document.querySelectorAll('table.let time.js-datetime')).slice(0, 2).map(t => t.textContent.trim()),
    };
  });
  ok(st.tabActive, 'the BAN tab strip does not mark "Let through" as the page');
  ok(st.tabs === 4, `the BAN tab strip has ${st.tabs} tabs, want 4`);
  ok(st.sections >= 11, `only ${st.sections} grounds are listed; every ground has a block, the empty ones too`);
  ok(st.nameOpen === true, 'the ground a stranger can use (a crawler by name) is not open');
  ok(st.nameRows.join() === '10.9.0.1,10.9.0.1,10.9.0.2', `the name ground lists ${st.nameRows.join()}, want the never-checked address first, once a site`);
  ok(st.nameNever.join() === 'true,true,false', `never-checked marks: ${st.nameNever.join()}, want the address that never met the challenge marked on both its sites`);
  // The same address on two sites: each row names its site above the path,
  // and a long host is clipped in the cell with the whole of it kept.
  ok(st.nameSites[0] === 'default' && /^a-rather-long-subdomain/.test(st.nameSites[1]) && st.nameSites[2] === 'default',
     `the rows do not name their sites: ${JSON.stringify(st.nameSites)}`);
  ok(st.siteClip[1] === true && st.siteFull[1] === 'a-rather-long-subdomain-for-the-clip-check.shop.ui-e2e.example',
     `the long site name is not clipped with its whole value kept: clipped ${st.siteClip[1]}, kept "${st.siteFull[1]}"`);
  ok(st.siteAbovePath.every(Boolean), `a site is not on the line above its path: ${st.siteAbovePath.join()}`);
  ok(/\//.test(st.pathHead), `the column that holds the site and the path is headed "${st.pathHead}"`);
  ok(st.nameBadge, 'the name ground does not say in its summary that an address was never checked');
  ok(st.faultOpen === true && st.faultMarked, '"no ground found" holds an address and does not stand out, open');
  ok(st.faultRows.join() === '10.9.0.4', `"no ground found" lists ${st.faultRows.join()}`);
  ok(st.lastReason === 'none' && st.firstReason === 'name', `the page opens with "${st.firstReason}" and closes with "${st.lastReason}", want the crawler names first and "no ground found" last`);
  ok(st.pathOpen === false, 'an exemption of the operator\'s own (a bypass path) is open before being asked for');
  ok(st.cookieTable === false && /4,000/.test(st.cookieText), 'the pass cookie is not a count without a list');
  ok(st.emptyOpen === false, 'a ground nothing passed on is open');
  ok(!st.pageScrolls, 'the page scrolls sideways at 1366 wide');
  ok(st.times.length > 0 && st.times.every(t => t.length > 0), `the times are not filled in: ${JSON.stringify(st.times)}`);

  // A long path is clipped in its cell, the whole of it a click away.
  await page.evaluate(() => { document.querySelector('details.let-sec[data-reason="path"]').open = true; });
  const clip = await page.evaluate(() => {
    const c = document.querySelector('details.let-sec[data-reason="path"] td.path .clamp-v:not(.cp-site)');
    return c ? { clipped: c.scrollWidth > c.clientWidth + 1, full: (c.dataset.fullValue || '').length,
                 scrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1 } : null;
  });
  ok(clip && clip.clipped && clip.full > 150, `the long path is not clipped with its whole value kept: ${JSON.stringify(clip)}`);
  ok(clip && !clip.scrolls, 'the long path makes the page scroll sideways');

  // The BAN button opens the shared dialog, naming the address.
  await page.click('details.let-sec[data-reason="name"] tr[data-ip="10.9.0.1"] form.js-ban-form button');
  await page.waitForSelector('dialog.ban-dialog[open]', { timeout: 5000 }).catch(() => {});
  const dlg = await page.evaluate(() => {
    const d = document.querySelector('dialog.ban-dialog');
    return d ? { open: d.open, text: d.textContent } : null;
  });
  ok(dlg && dlg.open, 'the BAN button did not open the BAN dialog');
  ok(dlg && /10\.9\.0\.1/.test(dlg.text), 'the BAN dialog does not name the address');
  if (SHOTS) await page.screenshot({ path: SHOTS + '/let-through-ban.png' });

  // The ground that should be empty is the last block of a long page, and
  // nobody keeps that page open: the bell's row for it is the way in.  It
  // names the count and the site, and lands on the ground, opened, in view.
  const seedErr = seedNotice();
  ok(seedErr === '', 'seeding the notice failed: ' + seedErr);
  await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  await page.click('#nbell-btn');
  await page.waitForSelector('#nbell-list .nbell-item[data-kind="let_through_fault"]', { timeout: 5000 }).catch(() => {});
  const row = await page.evaluate(() => {
    const a = document.querySelector('#nbell-list .nbell-item[data-kind="let_through_fault"]');
    return a ? { href: a.getAttribute('href'), cls: a.className,
                 title: (a.querySelector('.nbell-title') || {}).textContent || '',
                 body: (a.querySelector('.nbell-body') || {}).textContent || '' } : null;
  });
  ok(row, 'the bell lists no row for the requests let through on no ground');
  if (row) {
    ok(/\/admin\/let-through\/\?window=24#let-none$/.test(row.href), 'the row links to ' + row.href);
    ok(/sev-warn/.test(row.cls), 'the row is not a warning: ' + row.cls);
    ok(/\b2\b/.test(row.title), 'the row does not count the requests: ' + row.title);
    ok(/default 2/.test(row.body), 'the row does not name the site: ' + row.body);
    if (SHOTS) {
      try { await page.screenshot({ path: SHOTS + '/let-through-notice.png', clip: { x: 566, y: 0, width: 800, height: 420 } }); } catch (e) {}
    }
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.click('#nbell-list .nbell-item[data-kind="let_through_fault"]'),
    ]);
    const landed = await page.evaluate(() => {
      const d = document.getElementById('let-none');
      const r = d ? d.getBoundingClientRect() : null;
      return { hash: location.hash, path: location.pathname + location.search, open: d ? d.open : null,
               top: r ? Math.round(r.top) : null, vh: window.innerHeight,
               rows: d ? d.querySelectorAll('table.let tbody tr').length : 0 };
    });
    ok(/\/admin\/let-through\/\?window=24$/.test(landed.path) && landed.hash === '#let-none', `the row led to ${landed.path}${landed.hash}`);
    ok(landed.open === true && landed.rows === 1, `the ground is not open with its address: ${JSON.stringify(landed)}`);
    ok(landed.top !== null && landed.top >= 0 && landed.top < landed.vh, `the ground is not in view after the link (top ${landed.top} of ${landed.vh})`);
    if (SHOTS) await page.screenshot({ path: SHOTS + '/let-through-from-notice.png' });
  }

  await browser.close();
  if (fails.length) {
    console.log('FAIL let-through');
    for (const f of fails) console.log('  - ' + f);
    process.exit(1);
  }
  console.log('ok let-through');
})().catch(e => { console.error(e); process.exit(2); });
