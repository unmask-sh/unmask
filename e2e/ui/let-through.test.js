// BAN > Let through: what the site answered without a challenge, by the
// ground it passed on, with the addresses behind each ground.
//
// What has to hold on the page: the ground a stranger can use is open with
// its addresses, the one nothing shows to have met the challenge first and
// marked; "no ground found" stands out when it holds anything; the pass
// cookie is a count without a list; a long path does not widen the page; and
// the BAN button opens the dialog the other BAN pages use, naming the address.
//
// run.sh seeds the rows (10.9.0.1 - 10.9.0.4).
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_SHOT_DIR.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

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
      faultOpen: sec('none') ? sec('none').open : null,
      faultMarked: sec('none') ? sec('none').classList.contains('fault') && sec('none').classList.contains('has') : false,
      faultRows: rowsOf('none').map(tr => tr.dataset.ip),
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
  ok(st.nameRows.join() === '10.9.0.1,10.9.0.2', `the name ground lists ${st.nameRows.join()}, want the never-checked address first`);
  ok(st.nameNever.join() === 'true,false', `never-checked marks: ${st.nameNever.join()}, want only the first address marked`);
  ok(st.nameBadge, 'the name ground does not say in its summary that an address was never checked');
  ok(st.faultOpen === true && st.faultMarked, '"no ground found" holds an address and does not stand out, open');
  ok(st.faultRows.join() === '10.9.0.4', `"no ground found" lists ${st.faultRows.join()}`);
  ok(st.pathOpen === false, 'an exemption of the operator\'s own (a bypass path) is open before being asked for');
  ok(st.cookieTable === false && /4,000/.test(st.cookieText), 'the pass cookie is not a count without a list');
  ok(st.emptyOpen === false, 'a ground nothing passed on is open');
  ok(!st.pageScrolls, 'the page scrolls sideways at 1366 wide');
  ok(st.times.length > 0 && st.times.every(t => t.length > 0), `the times are not filled in: ${JSON.stringify(st.times)}`);

  // A long path is clipped in its cell, the whole of it a click away.
  await page.evaluate(() => { document.querySelector('details.let-sec[data-reason="path"]').open = true; });
  const clip = await page.evaluate(() => {
    const c = document.querySelector('details.let-sec[data-reason="path"] td.path .clamp-v');
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

  await browser.close();
  if (fails.length) {
    console.log('FAIL let-through');
    for (const f of fails) console.log('  - ' + f);
    process.exit(1);
  }
  console.log('ok let-through');
})().catch(e => { console.error(e); process.exit(2); });
