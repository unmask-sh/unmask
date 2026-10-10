// The ask page: with no model configured it says so; once the AI advisor's
// settings point at a provider, a question goes out with the tools, the
// provider's tool call is run against the install and its result goes back,
// and the answer lands on the page with the tools it used -- and is still
// there after a reload.  The provider here is a stub speaking the
// OpenAI-compatible shape.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_SHOT_DIR.
const puppeteer = require('puppeteer-core');
const http = require('http');
const path = require('path');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  // --- provider stub: asks for the bans, then answers with what it got ------
  const seen = [];
  const stub = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      let m = {};
      try { m = JSON.parse(body); } catch (e) {}
      seen.push(m);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const msgs = m.messages || [];
      const lastTool = msgs.filter(x => x.role === 'tool').pop();
      if (!lastTool) {
        // Slow enough for the page's pending state to be seen.
        setTimeout(() => {
          res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: '', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'bans', arguments: '{"limit":5}' } }] } }], usage: { prompt_tokens: 12, completion_tokens: 3 } }));
        }, 1500);
        return;
      }
      let count = '?';
      try { count = JSON.parse(lastTool.content).count; } catch (e) {}
      res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'E2E-ANSWER: the ban list has ' + count + ' rows. See /admin/bans/ for them.\n```\nbans count=' + count + '\n```' } }], usage: { prompt_tokens: 40, completion_tokens: 9 } }));
    });
  });
  await new Promise(r => stub.listen(0, '127.0.0.1', r));
  const stubURL = 'http://127.0.0.1:' + stub.address().port;

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1300, height: 900 },
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

  // Point the AI settings at the stub (the same form the advisor test uses).
  async function saveAI(enabled, provider, endpoint, key) {
    await page.goto(BASE + '/admin/settings/ai-advisor/', { waitUntil: 'networkidle2' });
    const submitted = await page.evaluate((enabled, provider, endpoint, key) => {
      const keyEl = document.querySelector('[name="ai_api_key"]');
      if (!keyEl) return 'no key field';
      const form = keyEl.form;
      const set = (n, v) => { const el = form.querySelector(`[name="${n}"]`); if (el) el.value = v; };
      const en = form.querySelector('[name="ai_enabled"]');
      if (en) en.checked = enabled;
      set('ai_provider', provider);
      set('ai_model', 'e2e-model');
      set('ai_endpoint', endpoint);
      keyEl.value = key;
      form.requestSubmit();
      return 'ok';
    }, enabled, provider, endpoint, key);
    if (submitted !== 'ok') return submitted;
    const resp = await page.waitForResponse(r => r.url().indexOf('/admin/settings/save') >= 0, { timeout: 10000 }).catch(() => null);
    if (resp && resp.status() >= 400) return 'save HTTP ' + resp.status() + ': ' + (await resp.text().catch(() => '')).slice(0, 200);
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 5000 }).catch(() => {});
    return 'ok';
  }

  // Off: the page says so and offers no composer.
  let saved = await saveAI(false, 'openai', stubURL, 'e2e-key');
  ok(saved === 'ok', 'could not save the AI settings (off): ' + saved);
  let resp = await page.goto(BASE + '/admin/ask/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ask/ status ${resp.status()}`);
  const off = await page.evaluate(() => ({ notice: !!document.getElementById('ask-off'), form: !!document.getElementById('ask-form'), link: !!document.querySelector('.hdr-ask') }));
  ok(off.notice && !off.form, 'with no model the page must show the notice and no composer');
  ok(off.link, 'the header link to the page is missing');

  // On: a question, through the stub, with the tool run on this install.
  saved = await saveAI(true, 'openai', stubURL, 'e2e-key');
  ok(saved === 'ok', 'could not save the AI settings (on): ' + saved);
  await page.goto(BASE + '/admin/ask/', { waitUntil: 'networkidle2' });
  const on = await page.evaluate(() => ({ form: !!document.getElementById('ask-form'), suggestions: document.querySelectorAll('.suggest button').length }));
  ok(on.form && on.suggestions === 3, 'the composer or its three suggestions are missing');
  await page.click('.suggest button');
  const filled = await page.evaluate(() => document.getElementById('ask-q').value.length > 5);
  ok(filled, 'a suggestion did not fill the question');
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E: how many bans?'; });
  await page.click('#ask-send');
  await sleep(300);
  const pending = await page.evaluate(() => ({ q: !!Array.from(document.querySelectorAll('#turns .q')).find(e => e.textContent === 'E2E: how many bans?'), pend: !!document.querySelector('#turns .a.pending'), disabled: document.getElementById('ask-send').disabled }));
  ok(pending.q && pending.pend && pending.disabled, 'the question is not shown as pending with the button held: ' + JSON.stringify(pending));
  let answered = null;
  for (let i = 0; i < 30 && !answered; i++) {
    await sleep(300);
    answered = await page.evaluate(() => {
      const a = Array.from(document.querySelectorAll('#turns .a:not(.pending)')).pop();
      if (!a || a.textContent.indexOf('E2E-ANSWER') < 0) return null;
      const link = a.querySelector('.txt a');
      return { text: a.querySelector('.txt').textContent, pre: !!a.querySelector('pre'), link: link ? link.getAttribute('href') : '', chips: Array.from(a.querySelectorAll('.tool-chip')).map(c => c.textContent), meta: a.querySelector('.a-meta').textContent, fail: a.classList.contains('fail') };
    });
  }
  ok(!!answered, 'no answer arrived');
  if (answered) {
    ok(/the ban list has \d+ rows/.test(answered.text), 'the answer does not carry the tool result: ' + answered.text);
    ok(answered.pre, 'the code fence was not shown as a block');
    ok(answered.link === '/unmask/admin/bans/', 'the admin path in the answer is not a link: ' + answered.link);
    ok(answered.chips.join(',') === 'bans', 'the tool chips: ' + answered.chips.join(','));
    ok(/52/.test(answered.meta) && /e2e-model/.test(answered.meta), 'the token line is missing: ' + answered.meta);
    ok(!answered.fail, 'the answer is marked failed');
  }
  ok(seen.length === 2 && Array.isArray(seen[0].tools) && seen[0].tools.length >= 5, 'the provider did not get the tools, or was called ' + seen.length + ' times');
  const released = await page.evaluate(() => !document.getElementById('ask-send').disabled);
  ok(released, 'the button stayed held after the answer');

  // The latest turn survives a reload, under the composer, with a copy.
  await page.reload({ waitUntil: 'networkidle2' });
  const kept = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, link: (function(){ const a = document.querySelector('#turns .a .txt a'); return a ? a.getAttribute('href') : ''; })(), text: (document.querySelector('#turns .a .txt') || {}).textContent || '', pre: !!document.querySelector('#turns .a pre'), copy: !!document.querySelector('#turns .a .a-copy'), folded: !!document.querySelector('#turns .a.folded'), tabs: Array.from(document.querySelectorAll('.ask-tabs a')).map(a => a.textContent.trim()), composerFirst: (function(){ const c = document.querySelector('.composer'), t = document.getElementById('turns'); return !!c && !!t && c.compareDocumentPosition(t) === Node.DOCUMENT_POSITION_FOLLOWING; })() }));
  ok(kept.turns === 1 && kept.text.indexOf('E2E-ANSWER') >= 0, 'the latest turn did not survive the reload: ' + JSON.stringify(kept));
  ok(kept.pre, 'the server-rendered turn does not show the code fence as a block');
  ok(kept.link === '/unmask/admin/bans/', 'the server-rendered turn does not link the admin path: ' + kept.link);
  ok(kept.copy && !kept.folded, 'the latest turn must carry a copy and stay whole: ' + JSON.stringify(kept));
  ok(kept.tabs.length === 2 && kept.composerFirst, 'the two tabs or the composer-first layout are missing: ' + JSON.stringify(kept));
  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'ask.png'), fullPage: true }); } catch (e) {}
  }

  // The history tab: the turn folded (its answer has several lines), the
  // button opens it; the copy puts "Q: ... A: ..." on the clipboard; the
  // delete removes the one turn after the dialog.
  resp = await page.goto(BASE + '/admin/ask/history/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ask/history/ status ${resp.status()}`);
  const hist = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, folded: !!document.querySelector('#turns .a.folded'), toggle: !!document.querySelector('#turns .a .a-toggle'), del: !!document.querySelector('#turns .a form[action$="/admin/ask/delete"]'), clear: !!document.querySelector('form[action$="/admin/ask/clear"]'), metaHidden: (function(){ const m = document.querySelector('#turns .a .a-meta'); return m ? getComputedStyle(m).display === 'none' : null; })() }));
  ok(hist.turns === 1 && hist.folded && hist.toggle && hist.del && hist.clear, 'the history tab is not as expected: ' + JSON.stringify(hist));
  ok(hist.metaHidden === true, 'a folded answer still shows its meta line');
  await page.click('#turns .a .a-toggle');
  const opened = await page.evaluate(() => ({ folded: !!document.querySelector('#turns .a.folded'), label: document.querySelector('#turns .a .a-toggle').textContent }));
  ok(!opened.folded && opened.label !== '', 'the toggle did not open the answer: ' + JSON.stringify(opened));
  // A headless page is not focused, so the clipboard refuses writes; the
  // write is captured instead and the text checked.
  await page.evaluate(() => { navigator.clipboard.writeText = function(t){ window.__copied = t; return Promise.resolve(); }; });
  await page.click('#turns .a .a-copy');
  await sleep(200);
  const copied = await page.evaluate(() => { const b = document.querySelector('#turns .a .a-copy'); return { clip: window.__copied || '', label: b.textContent, said: b.dataset.txtCopied }; });
  ok(/^Q: E2E: how many bans\?\n\nA: E2E-ANSWER/.test(copied.clip), 'the copy does not carry the question and answer: ' + JSON.stringify(copied.clip).slice(0, 120));
  ok(copied.label === copied.said, 'the copy button did not say it copied: ' + JSON.stringify(copied));
  await page.click('#turns .a form[action$="/admin/ask/delete"] button');
  await page.waitForSelector('.ux-dialog[open] .ux-dialog-btn.primary, .ux-dialog[open] .ux-dialog-btn.danger', { timeout: 5000 }).catch(() => {});
  const dialogText = await page.evaluate(() => (document.querySelector('.ux-dialog[open]') || {}).textContent || '');
  ok(dialogText.indexOf('E2E: how many bans?') >= 0, 'the delete dialog does not name the question: ' + dialogText.slice(0, 120));
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {}),
    page.click('.ux-dialog[open] .ux-dialog-btn.danger, .ux-dialog[open] .ux-dialog-btn.primary').catch(() => {}),
  ]);
  const afterDel = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, empty: !!document.getElementById('ask-empty'), path: location.pathname }));
  ok(afterDel.turns === 0 && afterDel.empty && /\/admin\/ask\/history\/$/.test(afterDel.path), 'the delete did not remove the turn: ' + JSON.stringify(afterDel));

  // Clearing: a second question, then the history's clear empties it.
  await page.goto(BASE + '/admin/ask/', { waitUntil: 'networkidle2' });
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E: again?'; });
  await page.click('#ask-send');
  let second = false;
  for (let i = 0; i < 30 && !second; i++) { await sleep(300); second = await page.evaluate(() => !!Array.from(document.querySelectorAll('#turns .a:not(.pending)')).find(a => a.textContent.indexOf('E2E-ANSWER') >= 0)); }
  ok(second, 'the second question got no answer');
  await page.goto(BASE + '/admin/ask/history/', { waitUntil: 'networkidle2' });
  await page.click('form[action$="/admin/ask/clear"] button');
  await page.waitForSelector('.ux-dialog[open] .ux-dialog-btn.primary, .ux-dialog[open] .ux-dialog-btn.danger', { timeout: 5000 }).catch(() => {});
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {}),
    page.click('.ux-dialog[open] .ux-dialog-btn.danger, .ux-dialog[open] .ux-dialog-btn.primary').catch(() => {}),
  ]);
  const cleared = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, empty: !!document.getElementById('ask-empty') }));
  ok(cleared.turns === 0 && cleared.empty, 'the history was not cleared: ' + JSON.stringify(cleared));

  // Leave the AI off for whichever test runs next.
  await saveAI(false, 'openai', stubURL, 'e2e-key');
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  stub.close();
  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('ask: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
