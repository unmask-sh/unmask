// The bot hunt's live tail draws an address the way the table below it does:
// flag, address, and the address popover (rDNS, geo, ASN) on hover.  The
// lines arrive over the event stream after the page has loaded, so the
// popover has to be bound to each as it is built.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
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
  const resp = await page.goto(BASE + '/admin/hunt/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);

  await page.click('#live-toggle');
  await sleep(1500);
  // A request made now reaches the page over the event stream.  A plain
  // request, not a second tab: the tail pauses while its own tab is hidden.
  await fetch(BASE + '/test/force-pow').then(r => r.text()).catch(() => {});
  let line = null;
  for (let i = 0; i < 40 && !line; i++) {
    await sleep(250);
    line = await page.evaluate(() => {
      const el = document.querySelector('#live-tail .ev .ip');
      if (!el) return null;
      return { cls: el.className, ip: el.dataset.ip || '', wired: el.dataset.ipWired === '1', text: el.textContent };
    });
  }
  ok(line, 'no line reached the live tail');
  if (line) {
    ok(/\bipclick\b/.test(line.cls) && line.ip !== '' && line.text.endsWith(line.ip),
      `the tail's address is not marked for the popover: ${JSON.stringify(line)}`);
    ok(line.wired, `the tail's address is not bound to the popover: ${JSON.stringify(line)}`);
    // Pointed at, it opens the popover.  The event goes to the element
    // itself, so a line arriving meanwhile cannot move it from under the
    // pointer.
    const hover = await page.evaluate(async () => {
      const el = document.querySelector('#live-tail .ev .ip.ipclick');
      if (!el) return { missing: true };
      const r = el.getBoundingClientRect();
      el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: r.left + 4, clientY: r.top + 4 }));
      await new Promise(res => setTimeout(res, 400));
      const pop = document.getElementById('ip-popover');
      return { shown: !!pop && pop.offsetParent !== null, text: pop ? pop.textContent.slice(0, 60) : '' };
    });
    ok(!hover.missing && hover.shown, `hovering the tail's address did not open the popover: ${JSON.stringify(hover)}`);
  }
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('hunt-live-tail: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
