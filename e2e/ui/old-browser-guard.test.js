// A browser too old to parse challenge.js is told so, instead of being left
// on the spinner.
//
// challenge.js is written for browsers of 2017 and later (async functions).
// An older one fails to parse the inlined script and runs none of it -- not
// even the error listener -- so the visitor sat on "Verifying your access"
// with a turning spinner for as long as they cared to wait.  The page's ES5
// bootstrap now waits a few seconds for the mark challenge.js sets as its
// first statement (window.__unmaskStarted) and, not seeing it, replaces the
// line with a note in English and Japanese and stops the spinner.
//
// The parse failure is produced here by answering the document request with
// the daemon's own page, the first statement of the challenge script broken;
// a page whose script runs must never show the note.
//
// The challenge page is not the admin, so this test does not log in; it
// drives /unmask/test/force-captcha, which run.sh enables on the throwaway
// instance.
//
// Driven by run.sh. Env: UI_E2E_BASE, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const PAGE = BASE + '/test/force-captcha';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const state = () => ({
  msg: document.getElementById('msg') ? document.getElementById('msg').textContent : null,
  spinner: (() => { const s = document.getElementById('spinner'); return s ? getComputedStyle(s).display : null; })(),
  started: !!window.__unmaskStarted,
  ja: !!document.querySelector('p[lang="ja"]'),
});

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 900 },
  });

  // 1. The script cannot be parsed: the note, both languages, no spinner.
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on('request', async (req) => {
    if (req.resourceType() === 'document' && req.url().indexOf('/test/force-captcha') >= 0) {
      try {
        const res = await fetch(req.url(), { headers: { 'User-Agent': await browser.userAgent() } });
        let html = await res.text();
        ok(html.indexOf('(async function(){') >= 0, '1: the served page inlines the challenge script');
        html = html.replace('(async function(){', '(async function(){ ]');
        return req.respond({ status: res.status, contentType: 'text/html; charset=utf-8', body: html });
      } catch (e) {
        return req.abort('failed');
      }
    }
    return req.continue();
  });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' });
  ok(errors.some(e => /SyntaxError/.test(e)), '1: the broken script fails to parse, errors: ' + JSON.stringify(errors));
  let st = await page.evaluate(state);
  ok(!st.started, '1: the challenge script did not run, got ' + JSON.stringify(st));
  ok(st.msg && st.msg.indexOf('Verifying') >= 0, '1: before the guard fires the page shows the HTML\'s own line, got ' + JSON.stringify(st.msg));
  await sleep(5800);
  st = await page.evaluate(state);
  ok(st.msg && st.msg.indexOf('cannot display this page') >= 0, '1: the guard replaces the line, got ' + JSON.stringify(st.msg));
  ok(st.ja, '1: the note is there in Japanese too');
  ok(st.spinner === 'none', '1: the spinner is stopped, got display=' + JSON.stringify(st.spinner));
  await page.close();

  // 2. A page whose script runs: the mark is set at once and the note never
  //    comes.
  const page2 = await browser.newPage();
  await page2.goto(PAGE, { waitUntil: 'domcontentloaded' });
  st = await page2.evaluate(state);
  ok(st.started, '2: the challenge script sets the mark as it starts, got ' + JSON.stringify(st));
  await sleep(5800);
  st = await page2.evaluate(state);
  ok(!(st.msg && st.msg.indexOf('cannot display') >= 0), '2: no note on a page whose script ran, got ' + JSON.stringify(st.msg));
  ok(!st.ja, '2: no Japanese note either');
  await page2.close();

  await browser.close();
  if (fails.length) {
    console.error('FAIL old-browser-guard:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok old-browser-guard');
})().catch(e => { console.error('ERROR old-browser-guard: ' + (e.stack || e)); process.exit(1); });
