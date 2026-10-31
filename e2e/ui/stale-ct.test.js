// A challenge page's proof-of-load token (ct) lasts fifteen minutes, and both
// builtin CAPTCHA paths hand it to the daemon.  A visitor who came back to the
// card after that was refused twice: the checkbox as "stale_challenge", which
// the page took for a low score and answered with the arithmetic fallback,
// whose question the daemon refused the same way -- and the page drew
// "undefined + undefined = ?" and accepted nothing.  Now the card says the
// check has expired: a refusal to something the visitor just did reloads the
// page once on its own (a second refusal in a row leaves a reload button), the
// page's own clock disables the card before the daemon would refuse, and the
// arithmetic copy comes in the visitor's language.
//
// The challenge page is not the admin, so this test does not log in; it drives
// /unmask/test/force-captcha, which run.sh enables on the throwaway instance.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const PAGE = BASE + '/test/force-captcha';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const STALE = { status: 403, contentType: 'application/json', body: '{"ok":0,"error":"stale_challenge"}' };
const LOW = { status: 403, contentType: 'application/json', body: '{"ok":0,"error":"low_score","score":0.1}' };

// Beacons go through fetch here, not sendBeacon, so their bodies are visible
// to the test (the protocol does not expose a sendBeacon body).
const noBeaconAPI = () => { Object.defineProperty(navigator, 'sendBeacon', { value: undefined }); };

// Wire a page: capture beacons, and answer /verify and /captcha/new with the
// canned response set on `canned` (null = let the daemon answer).
async function wire(page, canned, beacons) {
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const u = req.url();
    if (req.method() === 'POST' && u.indexOf('/api/debug') >= 0) beacons.push(req.postData() || '');
    if (req.method() === 'POST' && u.indexOf('/api/verify') >= 0 && canned.verify) return req.respond(canned.verify);
    if (req.method() === 'GET' && u.indexOf('/api/captcha/new') >= 0 && canned.question) return req.respond(canned.question);
    return req.continue();
  });
}

const card = (page) => page.evaluate(() => {
  const vis = (id) => { const e = document.getElementById(id); return !!e && e.style.display !== 'none'; };
  const strip = (id) => { const e = document.getElementById(id); return e ? e.textContent.replace(/​/g, '') : null; };
  const cb = document.getElementById('notRobot');
  return {
    expired: vis('ctExpired'), expiredMsg: strip('ctExpiredMsg'), reloadLabel: strip('ctExpiredReload'),
    math: vis('mathFallback'), mathQ: strip('mathQ'), desc: strip('captchaDesc'), err: vis('errMsg') ? strip('errMsg') : '',
    boxDisabled: cb ? cb.disabled : null, probe: window.__probe || 0, ct: window.UNMASK && window.UNMASK.ct,
  };
});
const short = (beacons) => JSON.stringify(beacons.map(b => b.slice(0, 200)));
const hasBeacon = (beacons, kind, method) => beacons.some(b =>
  b.indexOf('"phase":"error"') >= 0 && b.indexOf('"kind":"' + kind + '"') >= 0 && (!method || b.indexOf('"method":"' + method + '"') >= 0));
// Spoil the page's own token so the daemon itself answers stale_challenge.
const spoilCT = (page) => page.evaluate(() => {
  const c = window.UNMASK.ct; window.UNMASK.ct = c.slice(0, -1) + (c.slice(-1) === 'a' ? 'b' : 'a');
});
const fresh = async (page, url) => {
  await page.goto(url, { waitUntil: 'networkidle0' });
  await page.evaluate(() => { sessionStorage.clear(); window.__probe = 1; });
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(noBeaconAPI);
  const canned = { verify: null, question: null };
  const beacons = [];
  await wire(page, canned, beacons);

  // 1. The daemon refuses the checkbox because the page's token is stale (the
  //    token is spoiled here; the daemon's own answer is what the page reads).
  //    The card says so, takes no more input, records why, and reloads itself.
  await fresh(page, PAGE);
  beacons.length = 0;
  await spoilCT(page);
  let nav = page.waitForNavigation({ waitUntil: 'load', timeout: 6000 }).then(() => true, () => false);
  await page.click('#notRobot');
  await sleep(600);
  let st = await card(page);
  ok(st.expired, '1: the expired line is shown, got ' + JSON.stringify(st));
  ok(st.expiredMsg && st.expiredMsg.indexOf('expired') >= 0, '1: the line says the check expired, got ' + JSON.stringify(st.expiredMsg));
  ok(st.boxDisabled === true, '1: the box takes no more input');
  ok(!st.math, '1: the arithmetic fallback is not offered on a stale token');
  ok(hasBeacon(beacons, 'stale_challenge', 'behavioral'), '1: an error beacon names the stale token, saw ' + short(beacons));
  ok(await nav, '1: the page reloads itself after a stale refusal');
  st = await card(page);
  ok(!st.expired && st.boxDisabled === false && st.probe === 0, '1: the reloaded page is a fresh card, got ' + JSON.stringify(st));

  // 2. A second stale refusal within five minutes does not reload again: the
  //    button is the way out, and it works.
  await page.evaluate(() => { window.__probe = 2; });
  await spoilCT(page);
  nav = page.waitForNavigation({ waitUntil: 'load', timeout: 3000 }).then(() => true, () => false);
  await page.click('#notRobot');
  ok(!(await nav), '2: no second automatic reload in a row');
  st = await card(page);
  ok(st.expired && st.probe === 2, '2: the expired line stays with the button, got ' + JSON.stringify(st));
  ok(st.reloadLabel === 'Reload', '2: the button reads Reload, got ' + JSON.stringify(st.reloadLabel));
  nav = page.waitForNavigation({ waitUntil: 'load', timeout: 6000 }).then(() => true, () => false);
  await page.click('#ctExpiredReload');
  ok(await nav, '2: the button reloads the page');
  st = await card(page);
  ok(!st.expired && st.probe === 0, '2: a fresh card after the button, got ' + JSON.stringify(st));

  // 3. A low score sends the page to the arithmetic, whose question the daemon
  //    refuses for the stale token: the expired line, never "undefined".
  canned.verify = LOW; canned.question = STALE;
  await fresh(page, PAGE);
  beacons.length = 0;
  nav = page.waitForNavigation({ waitUntil: 'load', timeout: 6000 }).then(() => true, () => false);
  await page.click('#notRobot');
  await sleep(600);
  st = await card(page);
  ok(st.expired, '3: a refused question shows the expired line, got ' + JSON.stringify(st));
  ok((st.mathQ || '').indexOf('undefined') < 0, '3: the question is never drawn as undefined, got ' + JSON.stringify(st.mathQ));
  ok(hasBeacon(beacons, 'stale_challenge', 'captcha_new'), '3: an error beacon names the refused question, saw ' + short(beacons));
  ok(await nav, '3: the page reloads itself');
  canned.verify = null; canned.question = null;

  // 4. A question the daemon refuses for another reason (the address's budget)
  //    is reported with its status, the way a non-JSON answer is.
  canned.verify = LOW;
  canned.question = { status: 429, contentType: 'application/json', body: '{"ok":0,"error":"rate_limit"}' };
  await fresh(page, PAGE);
  beacons.length = 0;
  await page.click('#notRobot');
  await sleep(800);
  st = await card(page);
  ok(st.err.indexOf('(E-429)') >= 0, '4: a refused question says E-429, got ' + JSON.stringify(st.err));
  ok((st.mathQ || '').indexOf('undefined') < 0, '4: no undefined, got ' + JSON.stringify(st.mathQ));
  ok(hasBeacon(beacons, 'verify_bad_response', 'captcha_new'), '4: an error beacon carries the status, saw ' + short(beacons));
  canned.verify = null; canned.question = null;

  // 5. Japanese: the arithmetic's wording, the number prompt and the expired
  //    line come in the visitor's language.
  canned.verify = LOW;
  await fresh(page, PAGE + '?_preview_lang=ja');
  await page.click('#notRobot');
  await sleep(800);
  st = await card(page);
  ok(st.math, '5: the arithmetic is shown on a low score, got ' + JSON.stringify(st));
  ok(st.desc === '続行するには足し算の答えを入れてください。', '5: the arithmetic wording is Japanese, got ' + JSON.stringify(st.desc));
  ok(/^\d+ \+ \d+ = \?$/.test(st.mathQ || ''), '5: a real question, got ' + JSON.stringify(st.mathQ));
  await page.click('#submitBtn');
  await sleep(300);
  st = await card(page);
  ok(st.err === '数字を入れてください。', '5: the number prompt is Japanese, got ' + JSON.stringify(st.err));
  canned.verify = STALE;
  beacons.length = 0;
  await page.type('#answerInput', '7');
  nav = page.waitForNavigation({ waitUntil: 'load', timeout: 6000 }).then(() => true, () => false);
  await page.click('#submitBtn');
  await sleep(600);
  st = await card(page);
  ok(st.expired && st.expiredMsg === 'この確認の有効期限が切れました。ページを読み込み直すと続けられます。',
     '5: the expired line is Japanese, got ' + JSON.stringify(st.expiredMsg));
  ok(st.reloadLabel === '読み込み直す', '5: the button is Japanese, got ' + JSON.stringify(st.reloadLabel));
  ok(hasBeacon(beacons, 'stale_challenge', 'math'), '5: the beacon names the math path, saw ' + short(beacons));
  ok(await nav, '5: the page reloads itself');
  canned.verify = null;

  // 6. The page's own clock: with the token's life shortened to two seconds
  //    past the margin, the card gives up on its own, before any click, and
  //    does not reload until asked.
  const page6 = await browser.newPage();
  await page6.evaluateOnNewDocument(noBeaconAPI);
  await page6.evaluateOnNewDocument((secs) => {
    let u;
    Object.defineProperty(window, 'UNMASK', {
      configurable: true,
      get() { return u; },
      set(v) { if (v && typeof v === 'object') v.ct_valid_secs = secs; u = v; },
    });
  }, 17);
  const beacons6 = [];
  await wire(page6, { verify: null, question: null }, beacons6);
  await page6.goto(PAGE, { waitUntil: 'networkidle0' });
  await page6.evaluate(() => { window.__probe = 6; });
  st = await card(page6);
  ok(!st.expired && st.boxDisabled === false, '6: the card is live at first, got ' + JSON.stringify(st));
  nav = page6.waitForNavigation({ waitUntil: 'load', timeout: 4500 }).then(() => true, () => false);
  await sleep(2600);
  st = await card(page6);
  ok(st.expired && st.boxDisabled === true, '6: the card gives up when the token\'s time is up, got ' + JSON.stringify(st));
  ok(hasBeacon(beacons6, 'challenge_expired'), '6: an error beacon says the clock ran out, saw ' + short(beacons6));
  ok(!(await nav), '6: no reload until the visitor asks');
  st = await card(page6);
  ok(st.probe === 6, '6: still the same page, got ' + JSON.stringify(st));
  nav = page6.waitForNavigation({ waitUntil: 'load', timeout: 6000 }).then(() => true, () => false);
  await page6.click('#ctExpiredReload');
  ok(await nav, '6: the button reloads the page');

  await browser.close();
  if (fails.length) {
    console.error('FAIL stale-ct:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok stale-ct');
})().catch(e => { console.error('ERROR stale-ct: ' + (e.stack || e)); process.exit(1); });
