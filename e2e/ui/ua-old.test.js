// Browser-level check of the old-browser mark on a UA cell.
//
// The hunt log shows "Windows 10+ · Chrome 91", and whether 91 is last month's
// release or one from years ago is something the reader had to know.  A
// browser far behind its current release now has its name highlighted, with
// how many releases behind beside it ("−59"), and one that no longer ships
// says "EOL".  What only a browser can check: that the highlight is actually
// painted and inside the visible part of a column that clips, that the popover
// explains it, that the ranking above the log and the stats page wear the same
// mark, and that a row arriving over the live tail is drawn like the rest.
//
// run.sh seeds three serves: Chrome 91, Internet Explorer 11, and a Chrome
// numbered past any baseline (never old); and the first and the last of them
// again as two rows of the stats page's CAPTCHA cookie-reuse ranking.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(String(e.message || e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/hunt/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);

  // ---- the log rows ------------------------------------------------------
  const rows = await page.evaluate(() => {
    const read = bt => {
      const tr = document.querySelector('table.events tbody tr[data-bt="' + bt + '"]');
      const td = tr && tr.querySelector('td.ua');
      if (!td) return null;
      const old = td.querySelector('.ua-old');
      const lag = td.querySelector('.ua-lag');
      const tdBox = td.getBoundingClientRect();
      const oldBox = old ? old.getBoundingClientRect() : null;
      return {
        text: td.textContent.trim(),
        old: old ? old.textContent : null,
        lag: lag ? lag.textContent : null,
        bg: old ? getComputedStyle(old).backgroundColor : null,
        // the highlight starts inside the part of the cell that is shown
        startsInside: oldBox ? oldBox.left >= tdBox.left - 1 && oldBox.left < tdBox.right - 8 : null,
        note: td.getAttribute('data-note') || '',
        full: td.getAttribute('data-full-value') || '',
      };
    };
    return { chrome: read('uiOldChrome'), ie: read('uiOldIE'), cur: read('uiNewChrome') };
  });
  ok(rows.chrome && rows.ie && rows.cur, `the seeded rows are on the page: ${JSON.stringify(rows)}`);
  if (rows.chrome && rows.ie && rows.cur) {
    ok(/^Chrome 91−\d+$/.test(rows.chrome.old || ''), `Chrome 91 is highlighted with its count: ${JSON.stringify(rows.chrome.old)}`);
    ok(/^−\d{2,}$/.test(rows.chrome.lag || ''), `the count is a minus sign and the releases behind: ${JSON.stringify(rows.chrome.lag)}`);
    ok(rows.chrome.bg && rows.chrome.bg !== 'rgba(0, 0, 0, 0)' && rows.chrome.bg !== 'transparent', `the highlight is painted: ${rows.chrome.bg}`);
    ok(rows.chrome.startsInside === true, 'the highlight starts inside the visible part of the UA cell');
    ok(rows.chrome.note.length > 20 && /\d/.test(rows.chrome.note), `the cell carries the sentence for its popover: ${JSON.stringify(rows.chrome.note)}`);
    ok(/Chrome\/91\./.test(rows.chrome.full), 'the raw UA is still what the popover shows');
    ok(rows.ie.lag === 'EOL', `Internet Explorer is marked EOL: ${JSON.stringify(rows.ie.lag)}`);
    ok(rows.ie.note.length > 20, 'the Internet Explorer cell carries its sentence');
    ok(rows.cur.old === null && /Chrome 999/.test(rows.cur.text), `a current browser is not marked: ${JSON.stringify(rows.cur)}`);
    ok(rows.cur.note === '', `a current browser's cell has no note: ${JSON.stringify(rows.cur.note)}`);
  }

  // ---- the popover says why ----------------------------------------------
  const cell = await page.$('table.events tbody tr[data-bt="uiOldChrome"] td.ua');
  if (cell) {
    await cell.hover();
    await new Promise(r => setTimeout(r, 600));
    const pop = await page.evaluate(() => {
      const n = document.querySelector('.cellpop-pop .cellpop-note');
      return n ? n.textContent : null;
    });
    ok(pop && /\d+/.test(pop), `the popover carries the note: ${JSON.stringify(pop)}`);
    await page.mouse.move(5, 5);
  }

  // ---- the UA ranking above the log --------------------------------------
  const rank = await page.evaluate(() => {
    const cells = Array.from(document.querySelectorAll('.rank-card-ua td.key'));
    const of = re => cells.find(c => re.test(c.textContent));
    const c91 = of(/Chrome 91/), c999 = of(/Chrome 999/);
    return {
      found: !!c91 && !!c999,
      old: c91 ? !!c91.querySelector('.ua-sum .ua-old .ua-lag') : null,
      cur: c999 ? !!c999.querySelector('.ua-old') : null,
      oldNote: c91 ? (c91.getAttribute('data-note') || '') : null,
      curNote: c999 ? (c999.getAttribute('data-note') || '') : null,
    };
  });
  ok(rank.found, 'the UA ranking lists the seeded browsers');
  ok(rank.old === true, 'the ranking marks the old browser');
  ok(rank.cur === false, 'the ranking leaves the current browser unmarked');
  ok(rows.chrome && rank.oldNote === rows.chrome.note, `the ranking's cell carries the same sentence as the log's: ${JSON.stringify(rank.oldNote)}`);
  ok(rank.curNote === '', `the ranking's current browser has no note: ${JSON.stringify(rank.curNote)}`);
  const rcell = await page.evaluateHandle(() =>
    Array.from(document.querySelectorAll('.rank-card-ua td.key')).find(c => /Chrome 91/.test(c.textContent)) || null);
  if (rcell && rcell.asElement()) {
    const rel = rcell.asElement();
    // One request each puts the seeded browsers past the card's top ten:
    // open the card before pointing at the row.
    if (await rel.evaluate(c => c.offsetParent === null)) {
      await page.click('.rank-card-ua .rank-expand');
      await new Promise(r => setTimeout(r, 300));
    }
    await rel.evaluate(c => c.scrollIntoView({ block: 'center' }));
    await rel.hover();
    await new Promise(r => setTimeout(r, 600));
    const rpop = await page.evaluate(() => {
      const n = document.querySelector('.cellpop-pop .cellpop-note');
      return n ? n.textContent : null;
    });
    ok(rpop && rpop === rank.oldNote, `the ranking's popover explains the mark: ${JSON.stringify(rpop)}`);
    await page.mouse.move(5, 5);
  }

  if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-hunt.png', fullPage: true });

  // ---- the live tail ------------------------------------------------------
  // A request made now, with an old browser's UA, reaches the page over the
  // event stream and is drawn with the mark.
  await page.click('#live-toggle');
  await new Promise(r => setTimeout(r, 1500));
  // The visitor is a plain request from here, not a second tab: the tail
  // pauses while its own tab is in the background.
  await fetch(BASE + '/test/force-pow', {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36' },
  }).then(r => r.text()).catch(() => {});
  let tail = null;
  for (let i = 0; i < 40 && !tail; i++) {
    await new Promise(r => setTimeout(r, 250));
    tail = await page.evaluate(() => {
      const old = document.querySelector('#live-tail .ua .ua-old');
      if (!old) return null;
      const lag = old.querySelector('.ua-lag');
      return { old: old.textContent, lag: lag ? lag.textContent : null, line: old.closest('.ua').textContent };
    });
  }
  ok(tail, 'a row arriving over the live tail carries the mark');
  if (tail) {
    ok(/^Chrome 88−\d+$/.test(tail.old), `the tail highlights the browser half with its count: ${JSON.stringify(tail)}`);
    ok(/· Chrome 88/.test(tail.line), `the platform half stays outside the highlight: ${JSON.stringify(tail.line)}`);
  }
  if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-tail.png', clip: { x: 0, y: 0, width: 1500, height: 700 } });

  // ---- the stats page -----------------------------------------------------
  // Its UA columns wear the same mark, through its own copy of the popover
  // code -- so the explanation has to be checked there separately: on hover,
  // and in the pinned popover a click leaves behind.
  const sresp = await page.goto(BASE + '/admin/stats/?range=24h', { waitUntil: 'networkidle2' });
  ok(sresp.status() === 200, `/admin/stats/ status ${sresp.status()}`);
  const stat = await page.evaluate(() => {
    const cells = Array.from(document.querySelectorAll('td.bcd-ua'));
    const read = c => c && {
      old: (c.querySelector('.ua-old') || {}).textContent || null,
      note: c.getAttribute('data-note') || '',
      full: c.getAttribute('data-full-value') || '',
      shown: c.offsetParent !== null,
    };
    return {
      old: read(cells.find(c => /Chrome 91/.test(c.textContent))),
      cur: read(cells.find(c => /Chrome 999/.test(c.textContent))),
      // every marked cell on the page explains itself, whichever table it is in
      marked: cells.filter(c => c.querySelector('.ua-old')).length,
      explained: cells.filter(c => c.querySelector('.ua-old') && (c.getAttribute('data-note') || '').length > 20).length,
      noted: cells.filter(c => c.hasAttribute('data-note')).length,
    };
  });
  ok(stat.old && stat.cur, `the stats page lists the seeded browsers: ${JSON.stringify(stat)}`);
  if (stat.old && stat.cur) {
    ok(/^Chrome 91−\d+$/.test(stat.old.old || ''), `the stats page marks the old browser: ${JSON.stringify(stat.old)}`);
    ok(stat.old.note.length > 20 && /\d/.test(stat.old.note), `the marked stats cell carries its sentence: ${JSON.stringify(stat.old.note)}`);
    ok(stat.cur.old === null && stat.cur.note === '', `a current browser is neither marked nor explained there: ${JSON.stringify(stat.cur)}`);
    ok(stat.marked > 0 && stat.explained === stat.marked && stat.noted === stat.marked,
      `on the stats page ${stat.marked} cells are marked, ${stat.explained} of them explained, ${stat.noted} carry a note`);
  }
  const scell = await page.evaluateHandle(() =>
    Array.from(document.querySelectorAll('td.bcd-ua')).find(c => /Chrome 91/.test(c.textContent)) || null);
  if (scell && scell.asElement()) {
    const el = scell.asElement();
    await el.evaluate(c => c.scrollIntoView({ block: 'center' }));
    await el.hover();
    await new Promise(r => setTimeout(r, 600));
    const hov = await page.evaluate(() => {
      const p = document.querySelector('.cellpop-pop');
      const n = p && p.querySelector('.cellpop-note');
      const v = p && p.querySelector('.cellpop-val');
      return { note: n ? n.textContent : null, val: v ? v.textContent : null };
    });
    ok(hov.note && hov.note === stat.old.note, `hovering the marked stats cell explains the mark: ${JSON.stringify(hov)}`);
    ok(/Chrome\/91\./.test(hov.val || ''), `and still shows the raw UA: ${JSON.stringify(hov.val)}`);
    // The popover's surroundings, for a look at the real thing.
    const shot = async name => {
      if (!process.env.UI_E2E_SHOT) return;
      // clip is in page coordinates, the cell's box in the viewport's
      const r = await el.evaluate(c => { const b = c.getBoundingClientRect(); return { x: b.left + window.scrollX, y: b.top + window.scrollY }; });
      await page.screenshot({ path: process.env.UI_E2E_SHOT + name, clip: { x: Math.max(0, r.x - 300), y: Math.max(0, r.y - 150), width: 1150, height: 420 } });
    };
    await shot('-stats-hover.png');
    // Pinned: the clone a click leaves behind carries the sentence too.
    await el.click();
    await new Promise(r => setTimeout(r, 400));
    const pinned = await page.evaluate(() => {
      const notes = Array.from(document.querySelectorAll('.cellpop-pop .cellpop-note')).filter(n => n.offsetParent !== null);
      return notes.map(n => n.textContent);
    });
    ok(pinned.length > 0 && pinned.every(t => t === stat.old.note), `the pinned popover explains the mark: ${JSON.stringify(pinned)}`);
    await shot('-stats-pin.png');
    await page.keyboard.press('Escape');
    await page.mouse.move(5, 5);
  }
  if (process.env.UI_E2E_SHOT) await page.screenshot({ path: process.env.UI_E2E_SHOT + '-stats.png', fullPage: true });

  ok(jsErrors.length === 0, `page errors: ${jsErrors.join(' | ')}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL ua-old:\n  - ' + fails.join('\n  - '));
    process.exit(1);
  }
  console.log('PASS ua-old: an old browser is marked in the log, the ranking, the live tail and the stats page, and each mark is explained; a current one is not');
})().catch(e => { console.error('FAIL ua-old: ' + (e && e.stack || e)); process.exit(1); });
