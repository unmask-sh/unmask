// The CAPTCHA page's "I'm not a robot" box must reach the visitor unticked.
//
// A browser restores form state on a history navigation: press Back onto the
// challenge page and the box comes back ticked -- but a restored tick fires no
// change event, so the page sits there, already checked, doing nothing.  The
// visitor's only way out is to untick and retick it, which is what the operator
// reported from tool1-sg on 2026-09-09.  Reproduced in this browser against
// 0.1.41 (afterBack: checked=true) and fixed by autocomplete="off" on the input
// plus a reset before the change handler is wired.
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

const box = () => {
  const c = document.getElementById('notRobot');
  return c ? { checked: c.checked, disabled: c.disabled, ac: c.getAttribute('autocomplete') } : null;
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(PAGE, { waitUntil: 'networkidle0' });
  const first = await page.evaluate(box);
  ok(first !== null, 'the built-in checkbox is on the CAPTCHA page');
  if (first) {
    ok(first.checked === false, 'the box is unticked on a first load, got ' + JSON.stringify(first));
    ok(first.disabled === false, 'the box is enabled on a first load, got ' + JSON.stringify(first));
    ok(first.ac === 'off', 'the box opts out of form-state restoration, got autocomplete=' + JSON.stringify(first.ac));
  }

  // A tick the visitor left behind, then Back onto the page.  Setting .checked
  // without dispatching an event is exactly what a restore does.
  await page.evaluate(() => { document.getElementById('notRobot').checked = true; });
  await page.goto(BASE + '/healthz', { waitUntil: 'domcontentloaded' });
  await page.goBack({ waitUntil: 'networkidle0' });
  await new Promise(r => setTimeout(r, 400));
  const back = await page.evaluate(box);
  ok(back !== null, 'the checkbox is still there after a Back navigation');
  if (back) {
    ok(back.checked === false, 'a Back navigation must not leave the box ticked (that tick fires no change event and the page goes nowhere), got ' + JSON.stringify(back));
    ok(back.disabled === false, 'a Back navigation must not leave the box disabled, got ' + JSON.stringify(back));
  }

  // And the ordinary path still works: one click starts the verify.
  const posts = [];
  page.on('request', r => { if (r.method() === 'POST') posts.push(r.url().replace(/^https?:\/\/[^/]+/, '')); });
  await page.click('#notRobot');
  await new Promise(r => setTimeout(r, 1500));
  ok(posts.some(u => u.indexOf('/api/verify') >= 0), 'a click on the box must post the verify, saw: ' + JSON.stringify(posts));

  await browser.close();
  if (fails.length) {
    console.error('FAIL captcha-checkbox-restore:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok captcha-checkbox-restore');
})().catch(e => { console.error('ERROR captcha-checkbox-restore: ' + (e.stack || e)); process.exit(1); });
