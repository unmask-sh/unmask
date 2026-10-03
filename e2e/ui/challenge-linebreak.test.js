// Japanese and Korean on the challenge page break between phrases, never
// inside a word.
//
// Browsers may break Japanese between any two characters, and at the page's
// width the first-visit message came out as "…もう少々お" / "待ちください…" -- a
// word cut in half on the first screen a Japanese visitor sees.  challenge.html
// sets word-break:keep-all for lang ja and ko (breaks at spaces, after 、。
// and at the U+200B marks challenge.js puts in its longer Japanese sentences),
// with overflow-wrap:break-word for a run wider than the line.
//
// At phone and desktop widths, every line break in the PoW page's message and
// in the CAPTCHA card's texts must fall at one of those places -- never between
// two kana / kanji / hangul.  A break there means either the rule is gone or a
// sentence has a run too long for the line and needs a mark (U+200B).
//
// The public test pages (/unmask/test/force-pow, force-captcha) take
// ?_preview_lang, so no browser locale is needed.  The PoW page's verify POST
// is blocked: the page stays on the message instead of reloading.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// Where each line after the first starts inside the element's text: the
// characters on either side of the break.  Measured per character with a
// Range; a character that renders no box (a collapsed space, a U+200B at the
// end of a line) still counts as the character before the break.
function breaksIn(sel) {
  const el = document.querySelector(sel);
  if (!el || !el.getClientRects().length) return null;
  const r = document.createRange();
  const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  const out = [];
  let top = null, prev = '';
  for (let n = walk.nextNode(); n; n = walk.nextNode()) {
    for (let i = 0; i < n.data.length; i++) {
      r.setStart(n, i); r.setEnd(n, i + 1);
      const box = [...r.getClientRects()].find(b => b.width > 0);
      if (box) {
        const t = Math.round(box.top);
        if (top !== null && t > top + 2) out.push(prev + '|' + n.data[i]);
        top = t;
      }
      prev = n.data[i];
    }
  }
  return { text: el.textContent, wb: getComputedStyle(el).wordBreak, breaks: out };
}

const LETTER = /[぀-ヿ㐀-鿿가-힯]/;
const inWord = b => LETTER.test(b[0]) && LETTER.test(b[2]);

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
  });
  for (const lang of ['ja', 'ko']) {
    for (const width of [320, 360, 414, 1280]) {
      const page = await browser.newPage();
      await page.setViewport({ width, height: 800 });
      await page.setRequestInterception(true);
      page.on('request', q => (q.method() === 'POST' ? q.abort() : q.continue()));

      await page.goto(`${BASE}/test/force-pow?_preview_lang=${lang}`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => /[぀-ヿ가-힯]/.test(document.getElementById('msg').textContent), { timeout: 5000 });
      const msg = await page.evaluate(breaksIn, '#msg');
      const where = `${lang} ${width}px`;
      ok(msg !== null, `${where}: the PoW message is on the page`);
      if (msg) {
        ok(msg.wb === 'keep-all', `${where}: the message has word-break keep-all, got ${msg.wb}`);
        const bad = msg.breaks.filter(inWord);
        ok(bad.length === 0, `${where}: the message "${msg.text}" breaks inside a word at ${JSON.stringify(bad)}`);
      }

      await page.goto(`${BASE}/test/force-captcha?_preview_lang=${lang}`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => /[぀-ヿ가-힯]/.test(document.getElementById('notRobotLabel').textContent), { timeout: 5000 });
      for (const sel of ['#captchaTitle', '#captchaDesc', '#captchaNote', '#notRobotLabel']) {
        const got = await page.evaluate(breaksIn, sel);
        if (!got) continue;   // a preset without a note hides it
        const bad = got.breaks.filter(inWord);
        ok(bad.length === 0, `${where}: ${sel} "${got.text}" breaks inside a word at ${JSON.stringify(bad)}`);
      }
      await page.close();
    }
  }
  await browser.close();
  if (fails.length) {
    console.error('FAIL challenge-linebreak:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok challenge-linebreak');
})().catch(e => { console.error('ERROR challenge-linebreak: ' + (e.stack || e)); process.exit(1); });
