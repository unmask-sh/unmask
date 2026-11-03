// The pow_then_captcha chain passes end to end, and its CAPTCHA leg owes the
// proof-of-work the page solved first.
//
// The page's proof-of-load token signs the chain it ran, and the daemon takes
// no CAPTCHA answer for a chain that ran a proof-of-work without that proof:
// before this, the CAPTCHA leg was answerable on its own, which made the
// built-in CAPTCHA's pass the cheapest credential on the site -- a page fetch
// and one POST.  So the page carries the solved entry to the verify (as
// "pow"), the daemon checks it against the seed of this very page, and the
// pass it mints is CAPTCHA-grade.  A POST of a plausible signal under the
// page's own token, without the proof, is refused.
//
// The challenge page is not the admin, so this test does not log in; it drives
// /unmask/test/force-pow-then-captcha, which run.sh enables on the throwaway
// instance.  The box is ticked by a hand-shaped cursor movement, so the
// behavioral score clears; should it not, the arithmetic is typed instead,
// which owes the same proof and mints the same grade.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const PAGE = BASE + '/test/force-pow-then-captcha';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();
  const verifies = []; // { body, status, answer }
  page.on('request', r => {
    if (r.method() === 'POST' && r.url().indexOf('/api/verify') >= 0) verifies.push({ body: r.postData() || '' });
  });
  page.on('response', async r => {
    if (r.request().method() === 'POST' && r.url().indexOf('/api/verify') >= 0) {
      const v = verifies[verifies.length - 1];
      if (v) { v.status = r.status(); try { v.answer = await r.text(); } catch (_) { v.answer = ''; } }
    }
  });

  await page.goto(PAGE, { waitUntil: 'domcontentloaded' });
  const served = Date.now();
  // The chain's first leg: the proof-of-work, solved in a worker; then the
  // card.  A loaded runner takes a while over 2^18 hashes.
  await page.waitForFunction(() => {
    const c = document.getElementById('captcha');
    return c && getComputedStyle(c).display !== 'none' && document.getElementById('notRobot');
  }, { timeout: 60000 });
  const ct = await page.evaluate(() => (window.UNMASK && window.UNMASK.ct) || '');
  ok(/^\d+\.[0-9a-f]{16}\.pow_then_captcha\.[^.]*\.[0-9a-f]{64}$/.test(ct),
    'the page\'s token names the chain it ran, got ' + JSON.stringify(ct));
  const chain = await page.evaluate(() => window.UNMASK && window.UNMASK.challenge_mode);
  ok(chain === 'pow_then_captcha', 'the page ran the chain, got ' + JSON.stringify(chain));

  // The floor: two seconds of the token's clock between the page and any
  // answer (the daemon refuses a quicker one as too_fast).
  await sleep(Math.max(0, 2600 - (Date.now() - served)));

  // A fabricated signal under the page's own token, without the proof-of-work
  // the chain solved: refused, and the token is not spent by the refusal.
  const forged = await page.evaluate(async (base) => {
    const res = await fetch(base + '/api/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'x', ct: window.UNMASK.ct, sig: {
        hasMouseEvents: true, clickAt: 3000, windowSize: [1280, 900], screenSize: [1920, 1080],
        mouseTrail: [[10, 10, 1], [40, 33, 80], [70, 55, 160], [100, 77, 240], [130, 99, 320]] } }),
    });
    return { status: res.status, body: await res.text() };
  }, BASE);
  ok(forged.status === 403 && forged.body.indexOf('pow_required') >= 0,
    'a CAPTCHA answer without the chain\'s proof-of-work must be refused as pow_required, got ' + JSON.stringify(forged));

  // The real thing: a hand-shaped movement onto the box, then the tick.
  const box = await page.$('#notRobot');
  const b = await box.boundingBox();
  const tx = b.x + b.width / 2, ty = b.y + b.height / 2;
  let x = tx - 320, y = ty + 180;
  await page.mouse.move(x, y);
  const n = 28;
  for (let i = 1; i <= n; i++) {
    // Unequal steps, a curve, and gaps that scatter: what an arm does and a
    // driver stepping a path does not.
    const t = i / n;
    const ease = t * t * (3 - 2 * t);
    const wobble = Math.sin(t * Math.PI * 3) * 14 * (1 - t);
    x = tx - 320 * (1 - ease) + (i % 3) * 2.5;
    y = ty + 180 * (1 - ease) + wobble;
    await page.mouse.move(x, y);
    await sleep(9 + ((i * 7) % 23));
  }
  await page.mouse.move(tx, ty);
  await sleep(120);
  await page.mouse.click(tx, ty);
  let v = null;
  for (let i = 0; i < 60 && !v; i++) {
    await sleep(250);
    const last = verifies[verifies.length - 1];
    if (last && last.status) v = last;
  }
  ok(v !== null, 'the tick must post the verify and get an answer');
  if (v) {
    let sent = {};
    try { sent = JSON.parse(v.body); } catch (_) {}
    ok(sent.ct === ct, 'the verify carries the page\'s token');
    ok(/^\d+\.pow2\.[0-9a-z]+\.[0-9a-z]+$/.test(sent.pow || ''),
      'the verify carries the proof-of-work the page solved, got ' + JSON.stringify(sent.pow));
    if (v.status !== 200) {
      // The score fell short on this runner: the arithmetic is the way on,
      // typed, under the same proof.
      ok(v.status === 403 && (v.answer || '').indexOf('low_score') >= 0,
        'a behavioral refusal is a low score, got ' + v.status + ' ' + v.answer);
      await page.waitForFunction(() => {
        const q = document.getElementById('mathQ');
        return q && /\d+ \+ \d+/.test(q.textContent);
      }, { timeout: 15000 });
      const q = await page.evaluate(() => document.getElementById('mathQ').textContent);
      const m = q.match(/(\d+) \+ (\d+)/);
      await page.click('#answerInput');
      await sleep(300);
      await page.keyboard.type(String(Number(m[1]) + Number(m[2])), { delay: 90 });
      await sleep(600);
      const before = verifies.length;
      await page.click('#submitBtn');
      let mv = null;
      for (let i = 0; i < 60 && !mv; i++) {
        await sleep(250);
        const last = verifies[verifies.length - 1];
        if (verifies.length > before && last && last.status) mv = last;
      }
      ok(mv && mv.status === 200, 'the typed sum under the proof passes, got ' + JSON.stringify(mv));
      let msent = {};
      try { msent = JSON.parse((mv && mv.body) || '{}'); } catch (_) {}
      ok(/^\d+\.pow2\./.test(msent.pow || ''), 'the arithmetic carries the proof-of-work too');
    }
  }
  await sleep(800);
  const cookie = await page.evaluate(() => document.cookie);
  const bv = (cookie.match(/(?:^|;\s*)_bv=([^;]*)/) || [])[1] || '';
  const first = bv.split('~')[0];
  ok(/\.captcha$/.test(first), 'the pass the chain mints is CAPTCHA-grade, got ' + JSON.stringify(first));

  await browser.close();
  if (fails.length) {
    console.error('FAIL chain-pow-proof:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok chain-pow-proof');
})().catch(e => { console.error('ERROR chain-pow-proof: ' + (e.stack || e)); process.exit(1); });
