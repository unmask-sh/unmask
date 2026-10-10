// The dashboard's "right now" strip: rendered by the server with a first
// reading, then refreshed in place from /admin/api/now.  Lines written to the
// daemon's access-log socket must show up in the request tile within a refresh
// or two, the previous figures must survive a refresh (no blanking), and the
// auto-refresh switch must hold across a reload.
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

  const resp = await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ status ${resp.status()}`);

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
      spark: (grid.querySelector('.live[data-k="requests"] [data-f="spark"]') || {}).getAttribute
        ? grid.querySelector('.live[data-k="requests"] [data-f="spark"]').getAttribute('points') : '',
      errHidden: (document.getElementById('live-err') || {}).hidden,
    };
  });
  if (first.missing) {
    ok(false, 'the live strip is not on the dashboard');
  } else {
    ok(first.tiles.join(',') === 'requests,pass,bypass,serve,solve,deny,rate_limit',
      'tiles are not the seven outcomes in order: ' + first.tiles.join(','));
    ok(/^\d{2}:\d{2}:\d{2}$/.test(first.at || ''), 'the reading clock is not HH:MM:SS: ' + first.at);
    ok(/ON|on/.test(first.toggle || ''), 'auto-refresh is not on by default: ' + first.toggle);
    ok(first.spark && first.spark.split(' ').length === 60, 'the sparkline does not carry 60 buckets');
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
    ok(pass >= 3 && serve >= 3, `pass=${pass} serve=${serve}, expected 3 each from the fed lines`);
    const noFeedNote = await page.evaluate(() => document.getElementById('live-feed-off').hidden);
    ok(noFeedNote === true, 'the "feed off" note shows although lines arrive');
  }

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
