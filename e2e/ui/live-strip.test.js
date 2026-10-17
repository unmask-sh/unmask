// The dashboard's "right now" strip: rendered by the server with a first
// reading, then refreshed in place from /admin/api/now.  Lines written to the
// daemon's access-log socket must show up in the request tile within a refresh
// or two, the previous figures must survive a refresh (no blanking), and the
// auto-refresh switch must hold across a reload.  What the daemon answers a
// gated request with is counted from its serve event, not the line: a
// challenge page in the challenge tile, a deny page in the refused tile; the
// blocked tile is the difference (served + refused − solved − abandoned).
// The countdown beside the clock ends as a reading lands, and the recent
// table under the strip is read with the strip, not on a clock of its own.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, UI_E2E_OUT (the work dir's out/,
// beside which run.sh puts log.sock), CHROME_BIN.
const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SOCK = path.join(path.dirname(process.env.UI_E2E_OUT || '/tmp/x/out'), 'log.sock');

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// nginx writes the line as a syslog datagram; python has the unix-datagram
// socket node lacks.
function feed(n) {
  const py = `
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
for i in range(${n}):
    kind = "pow" if i % 2 == 0 else ""
    fc = "0" if i % 2 == 0 else "1"
    line = "<134>%s site=ui-e2e.example kind=%s fc=%s hp=0 ip=203.0.113.%d ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri= bp=0 scheme=https ua=Mozilla/5.0 live-strip" % (time.time(), kind, fc, 10 + i)
    s.sendto(line.encode(), sys.argv[1])
`;
  const r = spawnSync('python3', ['-I', '-c', py, SOCK], { encoding: 'utf8' });
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

  const resp = await page.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/live/ status ${resp.status()}`);

  const first = await page.evaluate(() => {
    const grid = document.getElementById('live-grid');
    if (!grid) return { missing: true };
    const tiles = Array.from(grid.querySelectorAll('.live[data-k]'));
    const req = grid.querySelector('.live[data-k="requests"] [data-f="last"]');
    return {
      tiles: tiles.map(t => t.dataset.k),
      requests: req ? req.textContent.trim() : null,
      at: (document.getElementById('live-at') || {}).textContent,
      toggle: (document.getElementById('live-toggle') || {}).textContent,
      bars: grid.querySelectorAll('.live[data-k="requests"] [data-f="bars"] rect').length,
      last30: (grid.querySelector('.live[data-k="requests"] [data-f="last30"]') || {}).textContent,
      errHidden: (document.getElementById('live-err') || {}).hidden,
    };
  });
  if (first.missing) {
    ok(false, 'the live strip is not on the dashboard');
  } else {
    ok(first.tiles.join(',') === 'requests,blocked,pass,bypass,serve,deny,solve,rate_limit',
      'tiles are not the eight figures in order: ' + first.tiles.join(','));
    ok(/^\d{2}:\d{2}:\d{2}$/.test(first.at || ''), 'the reading clock is not HH:MM:SS: ' + first.at);
    ok(/ON|on/.test(first.toggle || ''), 'auto-refresh is not on by default: ' + first.toggle);
    ok(first.bars === 30, 'the tile does not carry a bar per minute for 30 minutes: ' + first.bars);
    ok(/^[\d,]+$/.test(first.last30 || ''), 'the thirty-minute headline is not a number: ' + first.last30);
    ok(first.errHidden === true, 'the failure note shows on a healthy page');
  }

  // The JSON the page refreshes from.
  const api = await page.evaluate(async base => {
    const r = await fetch(base + '/admin/api/now', { credentials: 'same-origin' });
    return { status: r.status, cc: r.headers.get('cache-control'), body: await r.json() };
  }, BASE);
  ok(api.status === 200 && api.cc === 'no-store', `/admin/api/now ${api.status} ${api.cc}`);
  ok(api.body.available === true && api.body.step === 5 && api.body.window === 60, 'api shape: ' + JSON.stringify(api.body).slice(0, 120));
  ok(api.body.series && api.body.series.requests && api.body.series.requests.length === 60, 'api series');
  ok(api.body.series && api.body.series.blocked && api.body.series.blocked.length === 60 && 'blocked' in api.body.last30, 'api carries the blocked figure');

  // The countdown ends as a reading lands.  When the figures are written the
  // bar is full and the countdown at 0; right after, it starts over from 5
  // with an empty bar and steps down once a second.  (It ran a step behind:
  // the figures changed with a fifth of the bar still to fill, then the
  // countdown sat at 0 for a second and went on from 4.)
  const cd = await page.evaluate(() => new Promise(resolve => {
    const bar = document.getElementById('live-bar'), next = document.getElementById('live-next');
    const full = () => bar.getBoundingClientRect().width / bar.parentNode.getBoundingClientRect().width;
    const t0 = performance.now(), shown = [], reads = [];
    const mo = new MutationObserver(() => shown.push({ t: performance.now() - t0, v: next.textContent }));
    mo.observe(next, { childList: true, characterData: true, subtree: true });
    const onNow = () => {
      const at = { bar: full(), next: next.textContent };
      setTimeout(() => reads.push({ at, after: { bar: full(), next: next.textContent } }), 80);
    };
    document.addEventListener('unmask:now', onNow);
    setTimeout(() => { mo.disconnect(); document.removeEventListener('unmask:now', onNow); resolve({ shown, reads }); }, 11500);
  }));
  ok(cd.reads.length >= 2, `${cd.reads.length} readings in 11.5 s, expected 2`);
  cd.reads.forEach((r, i) => {
    ok(r.at.next === '0' && r.at.bar > 0.95, `reading ${i + 1} was written with the countdown at ${r.at.next} and the bar ${Math.round(r.at.bar * 100)}% full, expected 0 and full`);
    ok(r.after.next === '5' && r.after.bar < 0.2, `right after reading ${i + 1} the countdown showed ${r.after.next} with the bar ${Math.round(r.after.bar * 100)}% full, expected 5 and empty`);
  });
  const runs = [];
  cd.shown.forEach(s => { if (!runs.length || runs[runs.length - 1].v !== s.v) runs.push({ v: s.v, t: s.t }); });
  const seq = runs.map(r => r.v).join(' ');
  ok(seq.includes('5 4 3 2 1 0 5'), 'the countdown did not run 5 4 3 2 1 0: ' + seq);
  // Each figure for a second; 0 only while the reading is on its way.  (The
  // last run is cut by the end of the watch.)
  runs.slice(0, -1).forEach((r, i) => {
    const ms = Math.round(runs[i + 1].t - r.t);
    if (r.v === '0') ok(ms < 600, `the countdown sat at 0 for ${ms} ms`);
    else ok(ms > 600 && ms < 1400, `the countdown showed ${r.v} for ${ms} ms, expected a second`);
  });

  // The recent table under the strip is read with it, on every second turn
  // of the countdown, so its rows arrive with the figures.  Its own clock ran
  // on through a switch off and on (the strip reads at once then), and from
  // there it read between the strip's readings.
  await page.evaluate(() => new Promise(r => document.addEventListener('unmask:now', () => r(), { once: true })));
  await sleep(2500);
  const reads = [];
  const onReq = req => {
    const u = req.url();
    if (u.includes('/admin/api/now')) reads.push({ k: 'now', t: Date.now() });
    else if (u.includes('partial=recent')) reads.push({ k: 'recent', t: Date.now() });
  };
  page.on('request', onReq);
  await page.click('#live-toggle');
  await page.click('#live-toggle');
  await sleep(11000);
  page.off('request', onReq);
  const nows = reads.filter(r => r.k === 'now').map(r => r.t);
  const recents = reads.filter(r => r.k === 'recent').map(r => r.t);
  ok(recents.length >= 1, `the recent table was not read in the 11 s after the switch went off and on (the strip read ${nows.length} times)`);
  recents.forEach(t => {
    const gap = nows.length ? Math.min(...nows.map(n => Math.abs(n - t))) : Infinity;
    ok(gap < 200, `the recent table was read ${gap} ms away from the strip's nearest reading`);
  });
  ok(await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed')) === 'true', 'the switch is not back on');

  // Lines into the access-log socket show up within a refresh or two.
  const before = parseInt(String(first.requests || '0').replace(/,/g, ''), 10) || 0;
  if (!fs.existsSync(SOCK)) {
    ok(false, 'the daemon has no access-log socket at ' + SOCK);
  } else {
    const ferr = feed(6);
    ok(ferr === '', 'feeding the socket failed: ' + ferr);
    let after = before, pass = 0, serve = 0;
    for (let i = 0; i < 16 && after < before + 6; i++) {
      await sleep(1000);
      const s = await page.evaluate(() => {
        const g = document.getElementById('live-grid');
        const n = k => parseInt(g.querySelector('.live[data-k="' + k + '"] [data-f="last"]').textContent.replace(/,/g, ''), 10) || 0;
        return { r: n('requests'), p: n('pass'), s: n('serve') };
      });
      after = s.r; pass = s.p; serve = s.s;
    }
    ok(after >= before + 6, `requests tile ${before} -> ${after}, expected +6 within 16 s`);
    // The figure that moved flashed (the class stays after the animation).
    const flashed = await page.evaluate(() => document.querySelector('#live-grid .live[data-k="requests"] [data-f="last30"]').classList.contains('v-flash'));
    ok(flashed, 'the requests figure changed without a flash');
    ok(pass >= 3, `pass=${pass}, expected 3 from the fed lines`);
    const noFeedNote = await page.evaluate(() => document.getElementById('live-feed-off').hidden);
    ok(noFeedNote === true, 'the "feed off" note shows although lines arrive');
  }

  // Two challenge pages and a deny page, served for real: each lands in its
  // own tile (the thirty-minute figures, which nothing leaves during the
  // test), the refusal in the line under the map as well, and all three in
  // the blocked tile, since nobody clears them.
  const n30 = () => page.evaluate(() => {
    const g = document.getElementById('live-grid');
    const n = k => parseInt(g.querySelector('.live[data-k="' + k + '"] [data-f="last30"]').textContent.replace(/,/g, ''), 10) || 0;
    return { serve: n('serve'), deny: n('deny'), blocked: n('blocked') };
  });
  const nowApi = () => page.evaluate(async base => (await fetch(base + '/admin/api/now', { credentials: 'same-origin' })).json(), BASE);
  // The blocked figure before the clamp at zero: earlier tests may have
  // solved more challenges than they were served in this half hour.
  const rawBlocked = j => (j.last30.serve + j.last30.deny) - (j.last30.solve + j.last30.abandon);
  const apiBefore = await nowApi();
  const before30 = await n30();
  for (const u of ['/test/force-pow', '/test/force-pow', '/_deny/live-strip']) {
    await fetch(BASE + u, { headers: { 'User-Agent': 'Mozilla/5.0 live-strip' } }).then(r => r.text()).catch(() => {});
  }
  let after30 = before30;
  for (let i = 0; i < 16 && (after30.serve < before30.serve + 2 || after30.deny < before30.deny + 1); i++) {
    await sleep(1000);
    after30 = await n30();
  }
  ok(after30.serve === before30.serve + 2, `challenge tile ${before30.serve} -> ${after30.serve}, expected +2 (the deny page is no challenge)`);
  ok(after30.deny === before30.deny + 1, `refused tile ${before30.deny} -> ${after30.deny}, expected +1`);
  const apiAfter = await nowApi();
  const expBlocked = Math.max(0, rawBlocked(apiBefore) + 3);
  ok(apiAfter.last30.blocked === expBlocked, `api blocked30 ${apiAfter.last30.blocked}, expected ${expBlocked} (served ${apiAfter.last30.serve}, refused ${apiAfter.last30.deny}, solved ${apiAfter.last30.solve}, abandoned ${apiAfter.last30.abandon})`);
  ok(after30.blocked === apiAfter.last30.blocked, `blocked tile ${after30.blocked}, the api says ${apiAfter.last30.blocked}`);
  const refusedLine = await page.evaluate(() => {
    const el = document.getElementById('geo-refused');
    return el ? { links: el.querySelectorAll('a').length, text: el.textContent } : null;
  });
  ok(refusedLine && refusedLine.links >= 1, 'the refusal is not in the line under the map: ' + JSON.stringify(refusedLine));

  // Switch auto-refresh off: the countdown stops, the choice survives a reload.
  await page.click('#live-toggle');
  const paused = await page.evaluate(async () => {
    const n1 = document.getElementById('live-next').textContent;
    await new Promise(r => setTimeout(r, 2200));
    const n2 = document.getElementById('live-next').textContent;
    return { n1, n2, label: document.getElementById('live-toggle').textContent, pressed: document.getElementById('live-toggle').getAttribute('aria-pressed') };
  });
  ok(paused.n1 === paused.n2, `countdown kept running after the switch (${paused.n1} -> ${paused.n2})`);
  ok(paused.pressed === 'false' && /OFF|off/.test(paused.label), 'switch state: ' + paused.label);
  await page.reload({ waitUntil: 'networkidle2' });
  const held = await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed'));
  ok(held === 'false', 'the off choice did not survive a reload');
  await page.click('#live-toggle');
  const back = await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed'));
  ok(back === 'true', 'could not switch auto-refresh back on');

  // The strip as drawn, for a look by eye: out/ of the work dir (kept when the
  // run fails), or UI_E2E_SHOT_DIR when set.
  for (const dir of [process.env.UI_E2E_OUT, process.env.UI_E2E_SHOT_DIR]) {
    if (!dir) continue;
    try { await page.screenshot({ path: path.join(dir, 'live-strip.png'), clip: { x: 0, y: 0, width: 1400, height: 420 } }); } catch (e) {}
  }
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('live-strip: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
