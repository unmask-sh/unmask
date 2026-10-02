// Browser-level check of the old-browser mark on a UA cell.
//
// The hunt log shows "Windows 10+ · Chrome 91", and whether 91 is last month's
// release or one from years ago is something the reader had to know.  A
// browser far behind its current release now has its name highlighted, with
// how many releases behind ("−59") as a small badge on the name's upper right
// corner, and one that no longer ships says "EOL" there.  What only a browser
// can check: that the highlight is actually painted and inside the visible
// part of a column that clips, that the badge is small, sits on that corner
// and is not cut off by a cell that clips, that the popover explains it, that
// the ranking above the log and the stats page wear the same mark, and that a
// row arriving over the live tail is drawn like the rest.
//
// And what a cell does when it is too narrow for all of it.  Every one of
// these cells clips, and the badge used to sit in the clipped line: a cell
// wide enough for "Chrome 91" but not for the badge was cut with an ellipsis,
// and the ellipsis took the version with it ("Chrome 9...", "Chrome ...").
// The badge is now the first thing to give way: it is dropped whole, and the
// version is cut only when the name's own text no longer fits.  Checked in
// each kind of cell by laying it out a pixel narrower at a time, and by
// comparing how the name is painted, since nothing in the DOM says where an
// ellipsis ate a digit.
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

// badgeShape runs in the page, on an element that holds a mark: where the
// count sits against the highlighted name, how big it is, and whether the
// nearest ancestor that clips cuts its top off.
const badgeShape = cell => {
  const name = cell.querySelector('.ua-old-n'), lag = cell.querySelector('.ua-lag');
  if (!name || !lag) return null;
  const nb = name.getBoundingClientRect(), lb = lag.getBoundingClientRect();
  const text = document.createRange();
  text.selectNodeContents(lag);
  let clip = lag.parentElement;
  while (clip && !/hidden|clip|auto|scroll/.test(getComputedStyle(clip).overflowY)) clip = clip.parentElement;
  const cb = clip ? clip.getBoundingClientRect() : null;
  return {
    font: parseFloat(getComputedStyle(lag).fontSize), nameFont: parseFloat(getComputedStyle(name).fontSize),
    width: lb.width, rim: lb.width - text.getBoundingClientRect().width, nameHeight: nb.height,
    aboveTop: nb.top - lb.top, aboveBottom: nb.bottom - lb.bottom, gap: lb.left - nb.right,
    cutTop: cb ? cb.top - lb.top : 0,
    nameBg: getComputedStyle(name).backgroundColor,
  };
};
// The look that was asked for: small type, on the name's upper right corner,
// attached to it, narrow, and whole.  Every bound is one the stylesheet sets,
// not one the font does: how wide three letters are, and how far a name's box
// reaches above and below its line, change with whatever font the machine
// draws with -- and the runner's is not the developer's.
const okBadge = (s, where) => {
  ok(s, `${where}: the mark has a highlighted name and a badge`);
  if (!s) return;
  const j = JSON.stringify(s);
  ok(s.nameBg && s.nameBg !== 'rgba(0, 0, 0, 0)' && s.nameBg !== 'transparent', `${where}: the name's highlight is painted: ${j}`);
  ok(s.font <= s.nameFont * 0.8, `${where}: the badge is set in smaller type than the name: ${j}`);
  // Raised: its middle is above the name's middle, and its top is no lower
  // than a little way into the name.  A count set on the name's baseline has
  // its middle below the name's.
  ok(s.aboveTop + s.aboveBottom >= 1 && s.aboveTop >= -s.nameHeight / 4,
    `${where}: the badge sits on the name's upper corner, not along its baseline: ${j}`);
  ok(s.gap <= 0.5 && s.gap >= -6, `${where}: the badge is attached to the name's right edge: ${j}`);
  // Narrow: its own text in that small type, and a thin rim around it.
  ok(s.rim >= 0 && s.rim <= s.nameFont * 0.6, `${where}: the badge is narrow, its text and a thin rim: ${j}`);
  ok(s.cutTop <= 0.5, `${where}: the badge is not cut off at the top by the cell that clips it: ${j}`);
};

// nameDeltas runs in the page, on one screenshot of a sweep (below): how far
// the picture inside each rectangle is from the picture inside the first one
// -- the largest difference in any channel of any pixel.
const nameDeltas = async (png, want, clips) => {
  const bytes = Uint8Array.from(atob(png), c => c.charCodeAt(0));
  const shot = await createImageBitmap(new Blob([bytes], { type: 'image/png' }));
  const canvas = document.createElement('canvas');
  canvas.width = shot.width;
  canvas.height = shot.height;
  const cx = canvas.getContext('2d', { willReadFrequently: true });
  cx.drawImage(shot, 0, 0);
  const read = c => cx.getImageData(c.x, c.y, c.width, c.height).data;
  const ref = read(want);
  return clips.map(c => {
    const got = read(c);
    let far = got.length === ref.length ? 0 : 255;
    for (let i = 0; i < got.length && i < ref.length; i++) far = Math.max(far, Math.abs(got[i] - ref[i]));
    return far;
  });
};
// Two pictures of the same thing are not always the same bytes.  A copy that
// lies across a seam of the raster tiles (every 256 pixels) can have the
// rounded corners of its highlight come out a few levels off -- up to 7 of 255
// where it has been seen, and whether it is seen at all depends on the font
// the machine draws with.  What the comparison looks for is far coarser: an
// ellipsis in place of a digit, or the badge's fill over the name's, moves
// pixels by 56 levels and more.
const SAME_PICTURE = 24;

// fitSweep runs in the page.  It lays one marked cell out again and again in
// copies of its real container, a pixel narrower each time -- from "all of it
// fits" down to "not even the name does" -- and reports what each copy draws.
// make(w, html) builds a copy whose container is w pixels wide and returns its
// root and the element that holds the cell's markup.  What a copy should show
// is decided by the width its row really gets (.ua-fit) against the natural
// widths of the parts, measured in a copy with room to spare:
//   all   the row is as wide as name + badge: both are drawn
//   name  narrower than that, but the name's text fits: the text is whole,
//         the badge is not painted anywhere
//   clip  narrower than the text: the text runs past the box (an ellipsis)
// The copies sit at whole-pixel positions, so their text is rasterised alike
// and the caller can compare them as pictures.
const fitSweep = (makeSrc, html) => {
  const make = new Function('w', 'html', makeSrc);
  const stale = document.getElementById('fit-sweep');
  if (stale) stale.remove();
  const host = document.createElement('div');
  host.id = 'fit-sweep';
  host.style.cssText = 'position:absolute;left:0;top:0;width:1480px;height:880px;z-index:2147483000;background:#fff;overflow:hidden';
  document.body.appendChild(host);
  window.scrollTo(0, 0);
  const place = (i, root) => {
    const slot = document.createElement('div');
    slot.style.cssText = 'position:absolute;left:' + (16 + Math.floor(i / 19) * 360) + 'px;top:' + (16 + (i % 19) * 44) + 'px';
    slot.appendChild(root);
    host.appendChild(slot);
    return slot;
  };
  const parts = cell => {
    const fit = cell.querySelector('.ua-fit'), unit = cell.querySelector('.ua-fit > .ua-old');
    const name = cell.querySelector('.ua-old-n'), lag = cell.querySelector('.ua-lag');
    if (!fit || !unit || !name || !lag) return null;
    const text = document.createRange();
    text.selectNodeContents(name);
    return { lag, fb: fit.getBoundingClientRect(), ub: unit.getBoundingClientRect(), nb: name.getBoundingClientRect(),
             lb: lag.getBoundingClientRect(), tb: text.getBoundingClientRect() };
  };
  const probe = make(1000, html);
  const probeSlot = place(0, probe.root);
  const p0 = parts(probe.cell);
  if (!p0) { host.remove(); return { error: 'the cell is not the two-box row (.ua-fit > .ua-fit-h + .ua-old > .ua-old-n + .ua-lag)' }; }
  const toText = p0.tb.right - p0.fb.left, full = p0.lb.right - p0.fb.left, nameLeft = p0.nb.left - p0.fb.left;
  const lineHeight = Math.round(p0.ub.height);
  probeSlot.remove();
  const rows = [];
  const count = { all: 0, name: 0, clip: 0 };
  for (let w = Math.ceil(full) + 90; w > 8 && count.clip < 10 && rows.length < 57; w--) {
    const m = make(w, html);
    const slot = place(rows.length, m.root);
    const p = parts(m.cell);
    const avail = p.fb.width;
    // A tenth of a pixel either side of a threshold is left unjudged: layout
    // works in sixty-fourths and allows itself one of slack.
    const regime = avail >= full - 0.02 ? 'all' : (avail <= full - 0.1 && avail >= toText + 0.1) ? 'name' : avail <= toText - 0.1 ? 'clip' : '';
    if (!regime || (regime === 'all' && (avail > full + 4 || count.all >= 6))) { slot.remove(); continue; }
    count[regime]++;
    const hit = document.elementFromPoint(p.lb.left + p.lb.width / 2, p.lb.top + p.lb.height / 2);
    const painted = !!hit && (hit === p.lag || p.lag.contains(hit));
    const onLine = p.lb.top < p.ub.top + p.ub.height / 2;
    if (regime === 'all' && !rows.some(r => r.ref)) m.cell.setAttribute('data-fit-ref', '1');
    rows.push({
      regime, avail: +avail.toFixed(2), ref: m.cell.hasAttribute('data-fit-ref'),
      badge: painted ? (onLine ? 'shown' : 'stray') : 'hidden',
      whole: p.tb.right <= p.ub.right + 0.05,
      h: +m.cell.getBoundingClientRect().height.toFixed(2),
      // the name's text, short of its last two pixels (where the badge, when
      // shown, begins); the same size in every copy, so the pictures compare
      clip: { x: Math.floor(p.fb.left + nameLeft) - 1, y: Math.floor(p.ub.top),
              width: Math.floor(toText - nameLeft) - 1, height: lineHeight },
    });
  }
  return { toText: +toText.toFixed(2), full: +full.toFixed(2), count, rows };
};

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

  // fit: the sweep above for one kind of cell, and the pictures.  The name as
  // painted in every copy that should show it whole must be the name as
  // painted in the widest copy: an ellipsis that eats a digit moves no box, so
  // only the picture shows it.
  const fit = async (where, makeSrc, html) => {
    ok(html && /ua-fit/.test(html), `${where}: the marked cell's markup was found on the page`);
    if (!html) return;
    const info = await page.evaluate(fitSweep, makeSrc, html);
    if (info.error) { ok(false, `${where}: ${info.error}`); return; }
    const { rows, count } = info;
    ok(count.all >= 1 && count.name >= 5 && count.clip >= 5,
      `${where}: the sweep reached all three widths (${JSON.stringify(count)}, name text ${info.toText}px, with badge ${info.full}px)`);
    const say = list => list.map(r => r.avail + 'px').join(', ');
    const wrong = (regime, test) => rows.filter(r => r.regime === regime && test(r));
    let bad = wrong('all', r => r.badge !== 'shown' || !r.whole);
    ok(bad.length === 0, `${where}: with room for name and badge, both are drawn -- not at ${say(bad)}`);
    bad = wrong('name', r => r.badge !== 'hidden');
    ok(bad.length === 0, `${where}: a badge that does not fit is not painted at all -- but is at ${say(bad)} (${bad.map(r => r.badge).join(', ')})`);
    bad = wrong('name', r => !r.whole);
    ok(bad.length === 0, `${where}: while the name's text fits, the box holds all of it -- not at ${say(bad)}`);
    bad = wrong('clip', r => r.whole || r.badge !== 'hidden');
    ok(bad.length === 0, `${where}: narrower than the name's text, the text is cut and the badge is gone -- not at ${say(bad)}`);
    const hs = rows.map(r => r.h);
    ok(Math.max(...hs) - Math.min(...hs) <= 0.1, `${where}: the cell is the same height at every width (${Math.min(...hs)} to ${Math.max(...hs)}): a dropped badge adds no line`);
    // The pictures.  Keep the pointer off the copies: a hovered row changes colour.
    await page.mouse.move(1495, 895);
    const ref = rows.find(r => r.ref);
    ok(ref, `${where}: a copy with everything in it, to compare the others with`);
    if (ref) {
      const png = await page.screenshot({ clip: { x: 0, y: 0, width: 1480, height: 880 }, encoding: 'base64' });
      const far = await page.evaluate(nameDeltas, png, ref.clip, rows.map(r => r.clip));
      const cut = rows.filter((r, i) => r.regime !== 'clip' && far[i] > SAME_PICTURE);
      ok(cut.length === 0, `${where}: the version is painted whole wherever its text fits -- cut or covered at ${say(cut)} (off by ${cut.map(r => far[rows.indexOf(r)]).join(', ')} of 255)`);
      // And the comparison can tell: a copy too narrow for the name differs.
      const narrow = rows.map((r, i) => ({ r, far: far[i] })).filter(x => x.r.regime === 'clip').pop();
      if (narrow) ok(narrow.far > SAME_PICTURE, `${where}: a cell too narrow for the name is painted differently (the comparison sees an ellipsis; off by ${narrow.far} of 255)`);
      // The badge's shape, where it is shown.
      const cell = await page.$('#fit-sweep [data-fit-ref]');
      okBadge(await page.evaluate(badgeShape, cell), where);
      const over = await page.evaluate(c => {
        const lag = c.querySelector('.ua-lag'), b = lag.getBoundingClientRect();
        const hit = document.elementFromPoint(b.left + 1.5, b.top + b.height / 2);
        return !!hit && (hit === lag || lag.contains(hit));
      }, cell);
      ok(over, `${where}: the badge is painted over the name where the two overlap`);
    }
    if (process.env.UI_E2E_SHOT) await page.screenshot({ path: `${process.env.UI_E2E_SHOT}-fit-${where.replace(/\W+/g, '-')}.png`, clip: { x: 0, y: 0, width: 1480, height: 880 } });
    await page.evaluate(() => { const h = document.getElementById('fit-sweep'); if (h) h.remove(); });
  };

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
        // the highlight starts inside the part of the cell that is shown
        startsInside: oldBox ? oldBox.left >= tdBox.left - 1 && oldBox.left < tdBox.right - 8 : null,
        rowH: tr.getBoundingClientRect().height,
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
    ok(rows.chrome.startsInside === true, 'the highlight starts inside the visible part of the UA cell');
    // The mark does not make its row taller than its neighbours.
    ok(Math.abs(rows.chrome.rowH - rows.cur.rowH) <= 0.5 && Math.abs(rows.ie.rowH - rows.cur.rowH) <= 0.5,
      `a marked row is as tall as an unmarked one: ${rows.chrome.rowH} / ${rows.ie.rowH} / ${rows.cur.rowH}`);
    ok(rows.chrome.note.length > 20 && /\d/.test(rows.chrome.note), `the cell carries the sentence for its popover: ${JSON.stringify(rows.chrome.note)}`);
    ok(/Chrome\/91\./.test(rows.chrome.full), 'the raw UA is still what the popover shows');
    ok(rows.ie.lag === 'EOL', `Internet Explorer is marked EOL: ${JSON.stringify(rows.ie.lag)}`);
    ok(rows.ie.note.length > 20, 'the Internet Explorer cell carries its sentence');
    ok(rows.cur.old === null && /Chrome 999/.test(rows.cur.text), `a current browser is not marked: ${JSON.stringify(rows.cur)}`);
    ok(rows.cur.note === '', `a current browser's cell has no note: ${JSON.stringify(rows.cur.note)}`);
  }

  // ---- the popover says why ----------------------------------------------
  // shownNote: the sentence in the popover that is up now, once one is.  A
  // popover takes a moment to open, and a closed one keeps its last text --
  // so only one that is on screen counts.
  const shownNote = async () => {
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 150));
      const text = await page.evaluate(() => {
        const n = Array.from(document.querySelectorAll('.cellpop-pop .cellpop-note')).find(n => n.offsetParent !== null);
        return n ? n.textContent : null;
      });
      if (text) return text;
    }
    return null;
  };
  // park: the pointer off every cell, and the hover popover closed behind it.
  const park = async () => {
    await page.mouse.move(5, 5);
    await page.waitForFunction(
      () => !Array.from(document.querySelectorAll('.cellpop-pop')).some(p => p.offsetParent !== null),
      { timeout: 3000 }).catch(() => {});
  };
  const cell = await page.$('table.events tbody tr[data-bt="uiOldChrome"] td.ua');
  if (cell) {
    await cell.hover();
    const pop = await shownNote();
    ok(pop && /\d+/.test(pop), `the popover carries the note: ${JSON.stringify(pop)}`);
    await park();
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
      // The click leaves the pointer on the card, over one of the rows it has
      // just opened, and that row brings its own popover up: close it, or it
      // lies between the pointer and the cell hovered next.
      await park();
    }
    await rel.evaluate(c => c.scrollIntoView({ block: 'center' }));
    await rel.hover();
    const rpop = await shownNote();
    ok(rpop && rpop === rank.oldNote, `the ranking's popover explains the mark: ${JSON.stringify(rpop)}`);
    await park();
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

  // ---- too narrow for all of it: the badge goes first ---------------------
  // The three kinds of cell on this page, each in a copy of its own container:
  // the log's fixed-layout column, the ranking's fill-the-card column, the
  // tail's capped inline box.  Both marks in the log: a count and "EOL".
  const cellHTML = sel => page.evaluate(sel => { const c = document.querySelector(sel); return c ? c.innerHTML : ''; }, sel);
  const logCell = `
    const t = document.createElement('table'); t.className = 'events'; t.style.cssText = 'width:' + w + 'px;min-width:0;margin:0';
    t.innerHTML = '<tbody><tr><td class="ua cellpop cellpop-active"></td></tr></tbody>';
    const td = t.querySelector('td'); td.innerHTML = html; return { root: t, cell: td };`;
  await fit('log cell (a count)', logCell, await cellHTML('table.events tbody tr[data-bt="uiOldChrome"] td.ua'));
  await fit('log cell (EOL)', logCell, await cellHTML('table.events tbody tr[data-bt="uiOldIE"] td.ua'));
  const rankHTML = await page.evaluate(() => {
    const c = Array.from(document.querySelectorAll('.rank-card-ua td.key')).find(c => /Chrome 91/.test(c.textContent));
    return c ? c.querySelector('.ua-sum').innerHTML : '';
  });
  await fit('UA ranking cell', `
    const c = document.createElement('div'); c.className = 'rank-card rank-card-ua'; c.style.cssText = 'min-width:0;margin:0;padding:0;border:0;overflow:visible';
    c.innerHTML = '<div style="width:' + w + 'px"><table class="rank"><tbody><tr><td class="key cellpop cellpop-active"><span class="ua-sum"></span><span class="ua-raw"></span></td></tr></tbody></table></div>';
    c.querySelector('.ua-sum').innerHTML = html; return { root: c, cell: c.querySelector('td') };`, rankHTML);
  await fit('live tail line', `
    const c = document.createElement('div'); c.className = 'live-tail'; c.style.cssText = 'max-height:none;overflow:visible';
    c.innerHTML = '<div class="ev"><span class="ts">00:00:00</span><span class="ua" style="max-width:' + w + 'px"></span><span class="path">/</span></div>';
    const u = c.querySelector('.ua'); u.innerHTML = html; return { root: c, cell: u };`, await cellHTML('#live-tail .ua:has(.ua-old)'));

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

  // The stats page's cells give way the same way: a column that takes what
  // the table leaves it.
  const statHTML = await page.evaluate(() => {
    const c = Array.from(document.querySelectorAll('td.bcd-ua')).find(c => /Chrome 91/.test(c.textContent));
    return c ? c.innerHTML : '';
  });
  await fit('stats cell', `
    const t = document.createElement('table'); t.className = 'bcd-table bcd-cliptable'; t.style.cssText = 'width:' + w + 'px;margin:0';
    t.innerHTML = '<tbody><tr><td class="bcd-ua cellpop cellpop-active"></td></tr></tbody>';
    const td = t.querySelector('td'); td.innerHTML = html; return { root: t, cell: td };`, statHTML);

  // ---- the advisor's UA lines ----------------------------------------------
  // The same cell again, this time a flex item beside its request count.  No
  // seeded candidate uses an old browser, so the marked cell from the stats
  // page goes into a copy of a real line: what is under test is the line's
  // own layout around it.
  const aresp = await page.goto(BASE + '/admin/advisor/', { waitUntil: 'networkidle2' });
  ok(aresp.status() === 200, `/admin/advisor/ status ${aresp.status()}`);
  const hasLine = await page.evaluate(() => !!document.querySelector('table.cands .ua-list .uline .cellpop'));
  ok(hasLine, 'the advisor page lists a candidate with a UA line (run.sh seeds one)');
  if (hasLine) {
    await fit('advisor UA line', `
      const u = document.querySelector('table.cands .ua-list .uline').cloneNode(true);
      u.style.maxWidth = u.style.width = w + 'px';
      const c = u.querySelector('.cellpop'); c.innerHTML = html;
      const t = document.createElement('table'); t.className = 'cands'; t.style.cssText = 'width:auto;margin:0';
      t.innerHTML = '<tbody><tr><td><div class="ua-list"></div></td></tr></tbody>';
      t.querySelector('.ua-list').appendChild(u); return { root: t, cell: c };`, statHTML);
  }

  ok(jsErrors.length === 0, `page errors: ${jsErrors.join(' | ')}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL ua-old:\n  - ' + fails.join('\n  - '));
    process.exit(1);
  }
  console.log('PASS ua-old: an old browser is marked in the log, the ranking, the live tail and the stats page, and each mark is explained; a cell too narrow for the badge drops it and keeps the version; a current browser is not marked');
})().catch(e => { console.error('FAIL ua-old: ' + (e && e.stack || e)); process.exit(1); });
