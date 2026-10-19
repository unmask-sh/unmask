// The CAPTCHA page's generic failure text carries a code that says which of
// three things went wrong, because a support desk only ever gets the text in a
// screenshot.  A verify whose request never completes (an extension, a filter,
// the network) says E-NET; one answered with something other than JSON (a block
// page, a proxy, a dead daemon) says E-<status>.  Each also leaves an 'error'
// beacon with the same classification, so the hunt page shows what the visitor
// saw -- a transport failure used to leave no trace at all.
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

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();
  // Beacons go through fetch here, not sendBeacon, so their bodies are visible
  // to the test (the protocol does not expose a sendBeacon body).
  await page.evaluateOnNewDocument(() => { Object.defineProperty(navigator, 'sendBeacon', { value: undefined }); });

  let mode = 'pass';
  const beacons = [];
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const u = req.url();
    if (req.method() === 'POST' && u.indexOf('/api/debug') >= 0) beacons.push(req.postData() || '');
    if (req.method() === 'POST' && u.indexOf('/api/verify') >= 0) {
      if (mode === 'abort') return req.abort('failed');
      if (mode === 'html503') return req.respond({ status: 503, contentType: 'text/html', body: '<html><body>unavailable</body></html>' });
    }
    return req.continue();
  });

  const errText = () => page.evaluate(() => {
    const e = document.getElementById('errMsg');
    return e && e.style.display !== 'none' ? e.textContent : '';
  });
  const boxState = () => page.evaluate(() => {
    const c = document.getElementById('notRobot');
    return c ? { checked: c.checked, disabled: c.disabled } : null;
  });
  const short = () => JSON.stringify(beacons.map(b => b.slice(0, 160)));

  // 1. The request never completes.
  mode = 'abort';
  await page.goto(PAGE, { waitUntil: 'networkidle0' });
  beacons.length = 0;
  await page.click('#notRobot');
  await sleep(1500);
  let txt = await errText();
  ok(txt.indexOf('(E-NET)') >= 0, 'a verify that never completes shows the text with E-NET, got: ' + JSON.stringify(txt));
  const st = await boxState();
  ok(st && !st.disabled && !st.checked, 'the box is handed back for a retry, got ' + JSON.stringify(st));
  ok(beacons.some(b => b.indexOf('"phase":"error"') >= 0 && b.indexOf('"kind":"verify_network"') >= 0),
     'an error beacon records the network failure, saw: ' + short());

  // 2. The answer is not JSON.
  mode = 'html503';
  await page.goto(PAGE, { waitUntil: 'networkidle0' });
  beacons.length = 0;
  await page.click('#notRobot');
  await sleep(1500);
  txt = await errText();
  ok(txt.indexOf('(E-503)') >= 0, 'a non-JSON answer shows the text with its status, got: ' + JSON.stringify(txt));
  ok(beacons.some(b => b.indexOf('"kind":"verify_bad_response"') >= 0 && b.indexOf('"http_status":503') >= 0),
     'an error beacon records the bad response with its status, saw: ' + short());

  // 3. The ordinary path shows no code: a headless click scores low and falls
  //    back to the arithmetic question without any failure text.
  mode = 'pass';
  await page.goto(PAGE, { waitUntil: 'networkidle0' });
  await page.click('#notRobot');
  await sleep(1500);
  txt = await errText();
  ok(txt.indexOf('(E-') < 0, 'no code is shown when the verify answers, got: ' + JSON.stringify(txt));

  await browser.close();
  if (fails.length) {
    console.error('FAIL captcha-fail-code:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok captcha-fail-code');
})().catch(e => { console.error('ERROR captcha-fail-code: ' + (e.stack || e)); process.exit(1); });
