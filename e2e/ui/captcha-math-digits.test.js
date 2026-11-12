// The sum that follows a failed checkbox takes the answer in the digits the
// visitor's input method writes.
//
// The field checked /^\d+$/ and read the number with parseInt, which know
// the ASCII digits only.  A Japanese input method that is on writes １２, an
// Arabic keyboard ١٢: the sum was right and the page said "Please enter a
// number" -- to the very visitors the fallback is there to let through.
//
// One visit, and two answers asked of the daemon (the checkbox and the last
// sum): every address has a budget of them, shared by the specs that run
// from this machine.  The answers in between are answered here -- "wrong",
// so the page asks for another sum -- after reading the number the page
// posted, which is what the digits have to come to.
//
// Not the admin, so no login: /unmask/test/force-captcha, which run.sh
// enables on the throwaway instance.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const PAGE = BASE + '/test/force-captcha';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// n written with the digits whose zero is at code point zero.
const digits = (n, zero) => String(n).replace(/\d/g, d => String.fromCharCode(zero + Number(d)));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  // The sums the page posts.  While held, they are answered here.
  let held = true;
  const posted = [];
  await page.setRequestInterception(true);
  page.on('request', req => {
    if (req.method() === 'POST' && req.url().indexOf('/api/verify') >= 0) {
      let body = {};
      try { body = JSON.parse(req.postData() || '{}'); } catch (_) {}
      if ('answer' in body) {
        posted.push(body.answer);
        if (held) {
          return req.respond({ status: 200, contentType: 'application/json', body: '{"ok":0,"error":"wrong_answer"}' });
        }
      }
    }
    return req.continue();
  });

  // The question on the page once it is ready for an answer: its sum.
  const sum = async () => {
    await page.waitForFunction(() => /\d+ \+ \d+/.test(document.getElementById('mathQ').textContent) &&
      !document.getElementById('submitBtn').disabled && document.getElementById('answerInput').value === '', { timeout: 8000 });
    const [a, b] = (await page.$eval('#mathQ', e => e.textContent)).match(/\d+/g).map(Number);
    return a + b;
  };
  const answer = async text => {
    await page.type('#answerInput', text, { delay: 60 });
    await page.click('#submitBtn');
  };
  const errText = () => page.evaluate(() => {
    const e = document.getElementById('errMsg');
    return e && e.style.display !== 'none' ? e.textContent : '';
  });

  await page.goto(PAGE, { waitUntil: 'networkidle0' });
  // The checkbox clicked at once, which the daemon does not take from this
  // browser: the sum follows.
  await page.click('#notRobot');
  const math = await page.waitForSelector('#mathFallback', { visible: true, timeout: 10000 }).catch(() => null);
  ok(!!math, 'the sum was not shown after the checkbox, so nothing was checked');

  if (math) {
    // What the page posts for the right sum, written in each script.
    for (const [name, zero] of [['Arabic-Indic', 0x0660], ['Persian', 0x06F0], ['Devanagari', 0x0966], ['Thai', 0x0E50], ['ASCII', 0x30]]) {
      const s = await sum();
      const typed = digits(s, zero);
      posted.length = 0;
      await answer(typed);
      await page.waitForFunction(() => document.getElementById('submitBtn').disabled ||
        document.getElementById('errMsg').style.display !== 'none', { timeout: 5000 }).catch(() => {});
      for (let t0 = Date.now(); posted.length === 0 && Date.now() - t0 < 3000;) await sleep(50);
      ok(posted.length === 1 && posted[0] === s,
        `${name} digits: the sum ${s}, typed ${JSON.stringify(typed)}, was posted as ${JSON.stringify(posted)}; the page said ${JSON.stringify(await errText())}`);
    }

    // Not a number is still not a number: said on the page, nothing posted.
    await sum();
    posted.length = 0;
    await answer('twelve');
    await sleep(400);
    ok(posted.length === 0 && (await errText()) !== '', 'a word in place of the sum: nothing posted and a line saying so; posted ' + JSON.stringify(posted) + ', the page said ' + JSON.stringify(await errText()));
    await page.$eval('#answerInput', e => { e.value = ''; });

    // And the whole way with full-width digits: the daemon takes the sum.
    const s = await sum();
    // It refuses an answer that comes sooner after the question than a
    // person reads it (too_fast).
    await sleep(2300);
    held = false;
    posted.length = 0;
    await answer(digits(s, 0xFF10));
    const passed = await page.waitForFunction(
      () => window.__unmaskPassed === true || !/^\/unmask\/test\//.test(location.pathname),
      { timeout: 8000 }).then(() => true).catch(() => false);
    ok(passed, `full-width digits: the right sum (${s}, typed ${JSON.stringify(digits(s, 0xFF10))}) was not taken; posted ${JSON.stringify(posted)}, the page said ${JSON.stringify(await errText().catch(() => ''))}`);
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL captcha-math-digits:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok captcha-math-digits');
})().catch(e => { console.error('ERROR captcha-math-digits: ' + (e.stack || e)); process.exit(1); });
