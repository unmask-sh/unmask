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
  const held = []; // the requests of questions to be stopped, as they close
  const stub = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      let m = {};
      try { m = JSON.parse(body); } catch (e) {}
      seen.push(m);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const msgs = m.messages || [];
      // A question asking for a long answer gets one straight away: more
      // lines than the window holds.
      const lastUser = msgs.filter(x => x.role === 'user').pop();
      if (lastUser && String(lastUser.content).indexOf('E2E-LONG') >= 0) {
        const long = Array.from({ length: 80 }, (_, i) => 'E2E-LONG line ' + (i + 1)).join('\n');
        res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: long } }], usage: { prompt_tokens: 10, completion_tokens: 80 } }));
        return;
      }
      // A question to be stopped: the response is held until the request is
      // gone -- the daemon ends its call when the page stops the question.
      if (lastUser && String(lastUser.content).indexOf('E2E-SLOW') >= 0) {
        const late = setTimeout(() => { try { res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'E2E-SLOW: too late' } }] })); } catch (e) {} }, 20000);
        req.on('close', () => { clearTimeout(late); held.push(Date.now()); });
        return;
      }
      // A question about a rule gets one proposed straight away.
      if (lastUser && String(lastUser.content).indexOf('E2E-RULE') >= 0) {
        res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'E2E-RULE: /admin/settings/custom-rules/?new=1&label=e2e%20again&c=ip%3A198.51.100.0%2F24&action=captcha_only' } }], usage: { prompt_tokens: 10, completion_tokens: 5 } }));
        return;
      }
      const lastTool = msgs.filter(x => x.role === 'tool').pop();
      if (!lastTool) {
        // Slow enough for the page's pending state to be seen.
        setTimeout(() => {
          res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: '', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'bans', arguments: '{"limit":5}' } }, { id: 'c2', type: 'function', function: { name: 'bans', arguments: '{"limit":3}' } }] } }], usage: { prompt_tokens: 12, completion_tokens: 3 } }));
        }, 1500);
        return;
      }
      let count = '?';
      try { count = JSON.parse(lastTool.content).count; } catch (e) {}
      res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'E2E-ANSWER: the ban list has ' + count + ' rows, most from 203.0.113.5. See /admin/bans/ for them.\n```\nbans count=' + count + '\n```\nA rule for it: /admin/settings/custom-rules/?new=1&label=e2e%20rule&c=ip%3A203.0.113.5&action=captcha_only' } }], usage: { prompt_tokens: 40, completion_tokens: 9 } }));
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
  const on = await page.evaluate(() => ({ form: !!document.getElementById('ask-form'), suggestions: document.querySelectorAll('#ask-suggest option').length, rows: document.getElementById('ask-q').getAttribute('rows') }));
  ok(on.form && on.suggestions >= 5 && on.rows === '1', 'the composer, its examples pick or its one-line field are missing: ' + JSON.stringify(on));
  await page.select('#ask-suggest', await page.$eval('#ask-suggest option:nth-child(2)', o => o.value));
  const filled = await page.evaluate(() => document.getElementById('ask-q').value.length > 5);
  ok(filled, 'a suggestion did not fill the question');
  // The picks: the configured model is selected, the effort select carries
  // what the provider takes, and a pick rides along with the question.
  const picks = await page.evaluate(() => ({ model: (document.getElementById('ask-model') || {}).value, efforts: Array.from((document.getElementById('ask-effort') || { options: [] }).options).map(o => o.value) }));
  ok(picks.model === 'e2e-model' && picks.efforts.join(',') === ',low,medium,high', 'the model / effort picks are not as expected: ' + JSON.stringify(picks));
  // The effort's default says what runs (here: a model the table does not
  // know, so "the model's own").
  const defLabel = await page.$eval('#ask-effort option', o => o.textContent);
  ok(/\(.+\)/.test(defLabel), 'the effort default is not named: ' + defLabel);
  await page.select('#ask-effort', 'low');
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E: how many bans?'; });
  await page.click('#ask-send');
  await sleep(300);
  const pending = await page.evaluate(() => ({ q: !!Array.from(document.querySelectorAll('#turns .q')).find(e => e.textContent === 'E2E: how many bans?'), pend: !!document.querySelector('#turns .a.pending'), held: document.getElementById('ask-send').hidden && !document.getElementById('ask-stop').hidden }));
  ok(pending.q && pending.pend && pending.held, 'the question is not shown as pending with the send button given way to stop: ' + JSON.stringify(pending));
  let answered = null;
  for (let i = 0; i < 30 && !answered; i++) {
    await sleep(300);
    answered = await page.evaluate(() => {
      const a = Array.from(document.querySelectorAll('#turns .a:not(.pending)')).pop();
      if (!a || a.textContent.indexOf('E2E-ANSWER') < 0) return null;
      const link = a.querySelector('.txt a');
      return { text: a.querySelector('.txt').textContent, pre: !!a.querySelector('pre'), link: link ? link.getAttribute('href') : '', ip: (a.querySelector('.ipclick') || { dataset: {} }).dataset.ip || '', chips: Array.from(a.querySelectorAll('.tool-chip')).map(c => c.textContent), meta: a.querySelector('.a-meta').textContent, fail: a.classList.contains('fail') };
    });
  }
  ok(!!answered, 'no answer arrived');
  // The answer comes in tinted, and its question stays in view: the page no
  // longer throws the answer to the top, taking the question off the screen.
  if (answered) {
    await sleep(900);
    const arrival = await page.evaluate(() => {
      const a = Array.from(document.querySelectorAll('#turns .a')).pop();
      const q = a && a.previousElementSibling;
      const r = q ? q.getBoundingClientRect() : null;
      return { fresh: !!a && a.classList.contains('fresh'), q: !!q && q.classList.contains('q-row'), qTop: r ? Math.round(r.top) : null, vh: innerHeight };
    });
    ok(arrival.fresh, 'the arriving answer is not marked to show its arrival');
    ok(arrival.q && arrival.qTop !== null && arrival.qTop >= 0 && arrival.qTop < arrival.vh, 'the question went out of view when its answer came: ' + JSON.stringify(arrival));
  }
  ok(seen.some(m => m.reasoning_effort === 'low'), 'the effort picked on the page did not reach the provider');
  if (answered) {
    ok(/the ban list has \d+ rows/.test(answered.text), 'the answer does not carry the tool result: ' + answered.text);
    ok(answered.pre, 'the code fence was not shown as a block');
    ok(answered.link === '/unmask/admin/bans/', 'the admin path in the answer is not a link: ' + answered.link);
    // The two bans calls are one chip with their count.
    ok(answered.chips.join(',') === 'bans ×2', 'the tool chips: ' + answered.chips.join(','));
    ok(/52/.test(answered.meta) && /e2e-model/.test(answered.meta), 'the token line is missing: ' + answered.meta);
    ok(!answered.fail, 'the answer is marked failed');
    ok(answered.ip === '203.0.113.5', 'the address in the answer is not marked for the popover: ' + answered.ip);
  }
  // Hovering the address opens the hunt page's popover, naming it at once
  // (the lookup fills in behind).
  if (answered && answered.ip) {
    await page.hover('#turns .ipclick');
    await sleep(700);
    const pop = await page.evaluate(() => { const p = document.getElementById('ip-popover'); return p ? { shown: p.offsetParent !== null, text: p.textContent } : null; });
    ok(pop && pop.shown && pop.text.indexOf('203.0.113.5') >= 0, 'the address popover did not open: ' + JSON.stringify(pop));
    await page.mouse.move(5, 5);
  }
  // "Make this rule" opens the rule in a modal: the custom-rules tab's card
  // for it, edited in place and added without leaving the page; the button
  // then names the rule and opens the tab at it, the history shows it made,
  // and the tab lists the rule.
  if (answered) {
    const btnText = await page.evaluate(() => { const a = document.querySelector('#turns a.ask-rule'); return a ? a.textContent : ''; });
    ok(btnText !== '' && btnText.indexOf('\u2197') < 0, 'the rule button is missing, or still promises a new tab: ' + btnText);
    await page.click('#turns a.ask-rule');
    await page.waitForSelector('#cr-modal[open] #cr-modal-body [data-cr]', { timeout: 5000 }).catch(() => {});
    const card = await page.evaluate(() => { const c = document.querySelector('#cr-modal[open] #cr-modal-body [data-cr]'); return c ? { label: c.querySelector('.cr-label').value, vals: c.querySelector('.cc-values').value, act: c.querySelector('input[name=cr_action]').value, path: location.pathname } : null; });
    ok(!!card && card.label === 'e2e rule' && card.vals === '203.0.113.5' && card.act === 'captcha_only' && /\/admin\/ask\/$/.test(card.path), 'the modal does not carry the proposed rule: ' + JSON.stringify(card));
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'ask-rule-modal.png') }); } catch (e) {}
    }
    await page.focus('#cr-modal .cr-label');
    await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
    await page.keyboard.type('e2e rule from ask');
    // The edit changes the condition too: only the record on the turn ties
    // the rule to this answer then.
    await page.evaluate(() => { const v = document.querySelector('#cr-modal .cc-values'); v.value = '203.0.113.0/24'; v.dispatchEvent(new Event('input', { bubbles: true })); });
    await page.click('#cr-modal-save');
    await page.waitForSelector('#cr-modal-msg.ok', { timeout: 5000 }).catch(() => {});
    const saved = await page.evaluate(() => ({ msg: (document.getElementById('cr-modal-msg') || {}).textContent || '', added: !!document.querySelector('#turns a.ask-rule.added'), saveHidden: document.getElementById('cr-modal-save').hidden, cmdCopy: !!document.querySelector('#cr-modal-msg code.cmd > button.cmd-copy') }));
    ok(/nginx/.test(saved.msg) && saved.added && saved.saveHidden, 'the add did not report, or the button did not change: ' + JSON.stringify(saved));
    // The note arrives by innerHTML after the page loaded; the reload command in it still gets its copy button.
    ok(saved.cmdCopy, 'the saved note has no copy button beside the reload command');
    const made = await page.evaluate(() => { const a = document.querySelector('#turns a.ask-rule.added'); return a ? { text: a.textContent.trim(), href: a.getAttribute('href'), tab: document.getElementById('cr-modal-tab').getAttribute('href') } : null; });
    ok(!!made && made.text.indexOf('e2e rule from ask') >= 0 && made.text.indexOf('\u2197') >= 0 && /\/admin\/settings\/custom-rules\/#rule-[a-z0-9]+$/.test(made.href) && made.tab === made.href, 'the button does not name and open the added rule: ' + JSON.stringify(made));
    await page.click('#cr-modal-cancel');
    const tabPage = await browser.newPage();
    // The history draws the button made, as the page did after the add.
    await tabPage.goto(BASE + '/admin/ask/history/', { waitUntil: 'networkidle2' });
    const histMade = await tabPage.evaluate(() => { const a = document.querySelector('#turns a.ask-rule'); return a ? { added: a.classList.contains('added'), text: a.textContent.trim(), href: a.getAttribute('href') } : null; });
    ok(!!made && !!histMade && histMade.added && histMade.text === made.text && histMade.href === made.href, 'the history does not show the rule as made: ' + JSON.stringify(histMade));
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await tabPage.click('#turns .a .a-toggle'); await tabPage.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'ask-history-rule-made.png'), fullPage: true }); } catch (e) {}
    }
    // Its link lands on the rule, marked.
    await tabPage.goto(new URL(made ? made.href : '/unmask/admin/settings/custom-rules/', BASE).href, { waitUntil: 'networkidle2' });
    const target = await tabPage.evaluate(() => { const c = document.querySelector('#cr-list [data-cr]:target'); return c ? { name: (c.querySelector('.cr-v-name') || {}).textContent || '', mark: getComputedStyle(c).boxShadow } : null; });
    ok(!!target && target.name.trim() === 'e2e rule from ask' && target.mark !== 'none', 'the made button does not land on the rule: ' + JSON.stringify(target));
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await tabPage.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'ask-rule-target.png') }); } catch (e) {}
    }
    const listed = await tabPage.evaluate(() => Array.from(document.querySelectorAll('#cr-list [data-cr] .cr-v-name')).map(e => e.textContent.trim()));
    ok(listed.length === 1 && listed[0] === 'e2e rule from ask', 'the tab does not list the added rule: ' + JSON.stringify(listed));
    // Leave the list empty for the custom-rules test: a save of no cards.
    // (The page's CSRF shim puts the token on a same-origin fetch.)
    await tabPage.evaluate(async (base) => { await fetch(base + '/admin/settings/save?section=custom-rules', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' }); }, BASE);
    await tabPage.goto(BASE + '/admin/settings/custom-rules/', { waitUntil: 'networkidle2' });
    const left = await tabPage.evaluate(() => document.querySelectorAll('#cr-list [data-cr]').length);
    ok(left === 0, 'the added rule could not be cleared: ' + left + ' left');
    await tabPage.close();
  }
  ok(seen.length === 2 && Array.isArray(seen[0].tools) && seen[0].tools.length >= 5, 'the provider did not get the tools, or was called ' + seen.length + ' times');
  const released = await page.evaluate(() => !document.getElementById('ask-send').hidden && document.getElementById('ask-stop').hidden);
  ok(released, 'the send button did not come back after the answer');

  // A reload opens on the composer alone: the turn is the history tab's now.
  await page.reload({ waitUntil: 'networkidle2' });
  const kept = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, link: (function(){ const a = document.querySelector('#turns .a .txt a'); return a ? a.getAttribute('href') : ''; })(), text: (document.querySelector('#turns .a .txt') || {}).textContent || '', pre: !!document.querySelector('#turns .a pre'), copy: !!document.querySelector('#turns .a .a-copy'), folded: !!document.querySelector('#turns .a.folded'), tabs: Array.from(document.querySelectorAll('.ask-tabs a')).map(a => a.textContent.trim()), composerDocked: (function(){ const c = document.querySelector('.composer'), t = document.getElementById('turns'); return !!c && !!t && c.compareDocumentPosition(t) === Node.DOCUMENT_POSITION_PRECEDING && getComputedStyle(c).position === 'sticky'; })(), emptyNote: !!document.getElementById('ask-empty') }));
  ok(kept.turns === 0 && !kept.emptyNote, 'the ask tab must open on the composer alone after a reload: ' + JSON.stringify(kept));
  ok(kept.tabs.length === 2 && kept.composerDocked, 'the two tabs or the docked composer under the conversation are missing: ' + JSON.stringify(kept));
  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'ask.png'), fullPage: true }); } catch (e) {}
  }

  // The history tab: the turn folded (its answer has several lines), the
  // button opens it; the copy puts "Q: ... A: ..." on the clipboard; the
  // delete removes the one turn after the dialog.
  resp = await page.goto(BASE + '/admin/ask/history/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ask/history/ status ${resp.status()}`);
  const hist = await page.evaluate(() => ({ turns: document.querySelectorAll('#turns .a').length, folded: !!document.querySelector('#turns .a.folded'), toggle: !!document.querySelector('#turns .a .a-toggle'), del: !!document.querySelector('#turns .a form[action$="/admin/ask/delete"]'), clear: !!document.querySelector('form[action$="/admin/ask/clear"]'), metaHidden: (function(){ const m = document.querySelector('#turns .a .a-meta'); return m ? getComputedStyle(m).display === 'none' : null; })(), text: (document.querySelector('#turns .a .txt') || {}).textContent || '', pre: !!document.querySelector('#turns .a pre'), link: (function(){ const a = document.querySelector('#turns .a .txt a'); return a ? a.getAttribute('href') : ''; })(), copy: !!document.querySelector('#turns .a .a-copy'), chips: Array.from(document.querySelectorAll('#turns .a .tool-chip')).map(c => c.textContent), rule: (function(){ const a = document.querySelector('#turns a.ask-rule'); return a ? { added: a.classList.contains('added'), link: a.dataset.link || '' } : null; })() }));
  ok(hist.turns === 1 && hist.folded && hist.toggle && hist.del && hist.clear, 'the history tab is not as expected: ' + JSON.stringify(hist));
  // The rule added from it is gone (cleared above): the button offers it again.
  ok(!!hist.rule && !hist.rule.added && hist.rule.link.indexOf('/admin/settings/custom-rules/?new=1') === 0, 'with its rule removed, the history does not offer the rule again: ' + JSON.stringify(hist.rule));
  // The server-rendered turn: the answer whole in the DOM, the fence a
  // block, the admin path linked, a copy.
  ok(hist.text.indexOf('E2E-ANSWER') >= 0 && hist.pre && hist.link === '/unmask/admin/bans/' && hist.copy, 'the server-rendered turn is not as expected: ' + JSON.stringify({ pre: hist.pre, link: hist.link, copy: hist.copy }));
  ok(hist.metaHidden === true, 'a folded answer still shows its meta line');
  ok(hist.chips.join(',') === 'bans ×2', 'the history tab\'s tool chips: ' + hist.chips.join(','));
  // The folded answer's button says how many lines are hidden (from the
  // rendered overflow); opened, it offers to fold again, with no count.
  const foldedLabel = await page.evaluate(() => document.querySelector('#turns .a .a-toggle').textContent);
  ok(/\(.*[1-9][0-9]*.*\)$/.test(foldedLabel), 'the folded answer\'s button does not count the hidden lines: ' + JSON.stringify(foldedLabel));
  await page.click('#turns .a .a-toggle');
  const opened = await page.evaluate(() => ({ folded: !!document.querySelector('#turns .a.folded'), label: document.querySelector('#turns .a .a-toggle').textContent }));
  ok(!opened.folded && opened.label !== '' && !/\d/.test(opened.label), 'the toggle did not open the answer: ' + JSON.stringify(opened));
  // A headless page is not focused, so the clipboard refuses writes; the
  // write is captured instead and the text checked.
  await page.evaluate(() => { navigator.clipboard.writeText = function(t){ window.__copied = t; return Promise.resolve(); }; });
  await page.click('#turns .a .a-copy');
  await sleep(200);
  // An icon has no label to change: the button turns green and its
  // popover says so for a moment.
  const copied = await page.evaluate(() => { const b = document.querySelector('#turns .a .a-copy'); const pop = b.parentNode.querySelector('.ib-pop'); return { clip: window.__copied || '', label: pop ? pop.textContent : '', said: b.dataset.txtCopied, green: b.classList.contains('copied'), shown: pop ? getComputedStyle(pop).display !== 'none' : false, icon: !!b.querySelector('svg') }; });
  ok(/^Q: E2E: how many bans\?\n\nA: E2E-ANSWER/.test(copied.clip), 'the copy does not carry the question and answer: ' + JSON.stringify(copied.clip).slice(0, 120));
  ok(copied.label === copied.said && copied.green && copied.shown && copied.icon, 'the copy icon did not say it copied: ' + JSON.stringify(copied));
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

  // A question that fails offers a retry that sends it again on the same
  // turn: the form is pointed at a path that is not there, then put back.
  await page.goto(BASE + '/admin/ask/', { waitUntil: 'networkidle2' });
  await page.evaluate(() => { const f = document.getElementById('ask-form'); f.dataset.realAction = f.action; f.action = f.action.replace('/ask/send', '/ask/nowhere'); document.getElementById('ask-q').value = 'E2E: retry me'; });
  // Enter sends.
  await page.focus('#ask-q');
  await page.keyboard.press('Enter');
  let failedTurn = null;
  for (let i = 0; i < 20 && !failedTurn; i++) {
    await sleep(200);
    failedTurn = await page.evaluate(() => { const a = document.querySelector('#turns .a.fail'); return a ? { text: a.querySelector('.txt').textContent, retry: !!a.querySelector('.a-retry'), qs: document.querySelectorAll('#turns .q').length } : null; });
  }
  ok(!!failedTurn && failedTurn.retry && /HTTP 404/.test(failedTurn.text), 'a failed question does not offer a retry: ' + JSON.stringify(failedTurn));
  await page.evaluate(() => { const f = document.getElementById('ask-form'); f.action = f.dataset.realAction; });
  await page.click('#turns .a.fail .a-retry');
  let retried = null;
  for (let i = 0; i < 30 && !retried; i++) {
    await sleep(300);
    retried = await page.evaluate(() => { const a = document.querySelector('#turns .a:last-child'); if (!a || a.classList.contains('pending') || a.classList.contains('fail')) return null; return { text: a.querySelector('.txt').textContent, fails: document.querySelectorAll('#turns .a.fail').length, qs: document.querySelectorAll('#turns .q').length }; });
  }
  ok(!!retried && /E2E-ANSWER/.test(retried.text) && retried.fails === 0 && !!failedTurn && retried.qs === failedTurn.qs, 'the retry did not answer on the same turn: ' + JSON.stringify(retried));

  // A question out can be stopped: the send button gives way to a stop
  // button, which ends the request -- and with it the daemon's call to the
  // provider.  The turn says stopped, the question comes back to the field
  // selected, and the next question goes out at once.
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E-SLOW: stop me'; });
  await page.focus('#ask-q');
  await page.keyboard.press('Enter');
  let out = null;
  for (let i = 0; i < 20 && !out; i++) { await sleep(200); out = await page.evaluate(() => { const s = document.getElementById('ask-stop'), b = document.getElementById('ask-send'); return (s && !s.hidden && b.hidden && !!document.querySelector('#turns .a.pending')) ? { label: s.getAttribute('aria-label') } : null; }); }
  ok(!!out && !!out.label, 'the stop button did not come up while the question was out: ' + JSON.stringify(out));
  await sleep(600); // the daemon's call to the provider is out
  await page.click('#ask-stop');
  let stoppedTurn = null;
  for (let i = 0; i < 20 && !stoppedTurn; i++) {
    await sleep(200);
    stoppedTurn = await page.evaluate(() => { const a = document.querySelector('#turns .a.stopped'); if (!a) return null; const ta = document.getElementById('ask-q'); return { text: a.querySelector('.txt').textContent, want: document.getElementById('turns').dataset.txtStopped, field: ta.value, selected: ta.selectionStart === 0 && ta.selectionEnd === ta.value.length, sendBack: !document.getElementById('ask-send').hidden && document.getElementById('ask-stop').hidden, pending: document.querySelectorAll('#turns .a.pending').length }; });
  }
  ok(!!stoppedTurn && stoppedTurn.text === stoppedTurn.want && stoppedTurn.field === 'E2E-SLOW: stop me' && stoppedTurn.selected && stoppedTurn.sendBack && stoppedTurn.pending === 0, 'the stopped question is not shown as stopped with the question back in the field: ' + JSON.stringify(stoppedTurn));
  let closed = false;
  for (let i = 0; i < 25 && !closed; i++) { await sleep(200); closed = held.length > 0; }
  ok(closed, "the daemon's call to the provider did not end when the question was stopped");
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E: after the stop'; });
  await page.focus('#ask-q');
  await page.keyboard.press('Enter');
  let after = null;
  for (let i = 0; i < 30 && !after; i++) { await sleep(300); after = await page.evaluate(() => { const a = document.querySelector('#turns .a:last-child'); if (!a || a.classList.contains('pending')) return null; return { text: a.querySelector('.txt').textContent, stopped: a.classList.contains('stopped'), fail: a.classList.contains('fail') }; }); }
  ok(!!after && /E2E-ANSWER/.test(after.text) && !after.stopped && !after.fail, 'the question after the stop was not answered: ' + JSON.stringify(after));
  // The history keeps the stopped turn as stopped, with a retry.
  await page.goto(BASE + '/admin/ask/history/', { waitUntil: 'networkidle2' });
  const histStopped = await page.evaluate(() => { const a = document.querySelector('#turns .a.stopped'); return a ? { text: a.querySelector('.txt').textContent, want: document.getElementById('turns').dataset.txtStopped, retry: !!a.querySelector('.a-retry'), fail: a.classList.contains('fail') } : null; });
  ok(!!histStopped && histStopped.text === histStopped.want && histStopped.retry && !histStopped.fail, 'the history does not show the stopped turn: ' + JSON.stringify(histStopped));
  await page.goto(BASE + '/admin/ask/', { waitUntil: 'networkidle2' });

  // An answer longer than the window brings its question to the top, the
  // answer reading on below it -- not the answer's own top, which took the
  // question off the screen.
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E-LONG: a long one'; });
  await page.click('#ask-send');
  let long = false;
  for (let i = 0; i < 30 && !long; i++) { await sleep(300); long = await page.evaluate(() => !!Array.from(document.querySelectorAll('#turns .a:not(.pending)')).find(a => a.textContent.indexOf('E2E-LONG line 80') >= 0)); }
  ok(long, 'the long answer did not arrive');
  if (long) {
    await sleep(1200);
    const at = await page.evaluate(() => {
      const a = Array.from(document.querySelectorAll('#turns .a')).pop();
      const q = a.previousElementSibling.getBoundingClientRect();
      return { qTop: Math.round(q.top), aTop: Math.round(a.getBoundingClientRect().top), aBottom: Math.round(a.getBoundingClientRect().bottom), vh: innerHeight };
    });
    ok(at.qTop >= 0 && at.qTop < 60 && at.aTop > at.qTop && at.aBottom > at.vh, 'a long answer should bring its question to the top: ' + JSON.stringify(at));
  }

  // A fresh answer proposing a rule already on the list says it was made
  // from the start, and opens that rule.
  const listedRule = await page.evaluate(async (base) => {
    const body = new URLSearchParams({ cr_id: '', cr_key: 'draft', cr_label: 'e2e on the list', cr_enabled: '1', cr_action: 'captcha_only', cr_rate: '', cr_rate_action: '', cc_draft_kind: 'ip', cc_draft_values: '198.51.100.0/24', cc_draft_memo: '' });
    const r = await fetch(base + '/admin/settings/save?section=custom-rules-add', { method: 'POST', credentials: 'same-origin', headers: { 'Accept': 'application/json' }, body: body });
    return r.json();
  }, BASE);
  ok(listedRule && listedRule.ok && listedRule.rule && listedRule.rule.id, 'the rule for the fresh answer could not be added: ' + JSON.stringify(listedRule));
  await page.evaluate(() => { document.getElementById('ask-q').value = 'E2E-RULE: is it there?'; });
  await page.click('#ask-send');
  let fresh = null;
  for (let i = 0; i < 30 && !fresh; i++) {
    await sleep(300);
    fresh = await page.evaluate(() => { const a = Array.from(document.querySelectorAll('#turns .a:not(.pending)')).find(e => e.textContent.indexOf('E2E-RULE') >= 0); const b = a && a.querySelector('a.ask-rule'); return b ? { added: b.classList.contains('added'), text: b.textContent.trim(), href: b.getAttribute('href') } : null; });
  }
  ok(!!fresh && fresh.added && fresh.text.indexOf('e2e on the list') >= 0 && !!listedRule.rule && fresh.href === '/unmask/admin/settings/custom-rules/#rule-' + listedRule.rule.id, 'a fresh answer does not show its rule as made: ' + JSON.stringify(fresh));
  await page.evaluate(async (base) => { await fetch(base + '/admin/settings/save?section=custom-rules', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' }); }, BASE);

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
