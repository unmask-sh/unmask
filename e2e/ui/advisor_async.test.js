// The model is asked without leaving the page.
//
// Click "Ask the model" and the page must stay where it is: the bar turns
// into a progress line, the eligible rows show an "analysing" spinner, and
// when the (stub) provider answers, the rows fill in with the priority and
// reasoning -- same URL, no navigation.  The swapped-in rows must keep the
// IP popover and the BAN dialog (the shared partials re-wire them), and a
// reload afterwards shows the stored result without a spinner.
//
// A provider stub is started here on 127.0.0.1 (the harness daemon runs on
// the same host) and saved through settings > AI advisor; the settings are
// put back at the end so advisor.test.js's "no key" assumptions hold for
// the next run.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');
const http = require('http');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SEED_IP = '203.0.113.26';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  // --- provider stub: answers after 3s so the spinner state is observable --
  let calls = 0;
  const stub = http.createServer((req, res) => {
    calls++;
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      setTimeout(() => {
        const answer = JSON.stringify({ reviews: [{ target: SEED_IP, priority: 'high', reasoning: 'E2E-REASON-OK' }], nominations: [] });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ stop_reason: 'end_turn', content: [{ type: 'text', text: answer }] }));
      }, 3000);
    });
  });
  await new Promise(r => stub.listen(0, '127.0.0.1', r));
  const stubURL = 'http://127.0.0.1:' + stub.address().port;

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(String(e.message || e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // --- point the AI advisor at the stub --------------------------------------
  async function saveAI(enabled, endpoint, key) {
    await page.goto(BASE + '/admin/settings/ai-advisor/', { waitUntil: 'networkidle2' });
    const submitted = await page.evaluate((enabled, endpoint, key) => {
      const keyEl = document.querySelector('[name="ai_api_key"]');
      if (!keyEl) return 'no key field';
      const form = keyEl.form;
      const set = (n, v) => { const el = form.querySelector(`[name="${n}"]`); if (el) el.value = v; };
      const en = form.querySelector('[name="ai_enabled"]');
      if (en) en.checked = enabled;
      set('ai_provider', 'anthropic');
      set('ai_model', 'claude-opus-5');
      set('ai_endpoint', endpoint);
      keyEl.value = key;
      form.requestSubmit();
      return 'ok';
    }, enabled, endpoint, key);
    if (submitted !== 'ok') return submitted;
    // Read the save response itself: a 4xx here is the harness telling us
    // why the settings did not take (config path, form, CSRF).
    const resp = await page.waitForResponse(r => r.url().indexOf('/admin/settings/save') >= 0, { timeout: 10000 }).catch(() => null);
    if (resp && resp.status() >= 400) return 'save HTTP ' + resp.status() + ': ' + (await resp.text().catch(() => '')).slice(0, 200);
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 5000 }).catch(() => {});
    return 'ok';
  }
  const saved = await saveAI(true, stubURL, 'e2e-key');
  ok(saved === 'ok', 'could not save the AI advisor settings: ' + saved);

  // --- the click stays on the page ------------------------------------------
  let resp = await page.goto(BASE + '/admin/advisor/?window=24', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/advisor/ status ${resp.status()}`);
  const before = page.url();
  const hasForm = await page.evaluate(() => !!document.querySelector('#ai-run-form button'));
  if (!hasForm) {
    ok(false, 'the page does not offer the model button after saving the key');
  } else {
    await page.click('#ai-run-form button');
    await sleep(500);
    const mid = await page.evaluate((ip) => {
      const row = Array.from(document.querySelectorAll('#cands-body tr'))
        .find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
      return {
        url: location.href,
        barSpin: !!document.querySelector('#ai-bar-state .ai-spin'),
        elapsed: (document.getElementById('ai-elapsed') || {}).textContent || '',
        rowWait: !!(row && row.querySelector('.ai-slot[data-ai="1"] .ai-wait')),
        disabled: !!(document.querySelector('#ai-run-form button') || {}).disabled,
      };
    }, SEED_IP);
    ok(mid.url === before, `the click navigated: ${mid.url}`);
    ok(mid.barSpin, 'the bar shows no progress spinner during the run');
    ok(mid.rowWait, 'the seed row shows no "analysing" spinner during the run');
    ok(mid.disabled, 'the button stays enabled during the run');

    // --- the answer lands in place ------------------------------------------
    let done = null;
    for (let i = 0; i < 40 && !done; i++) {
      await sleep(500);
      done = await page.evaluate((ip) => {
        const row = Array.from(document.querySelectorAll('#cands-body tr'))
          .find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
        const reason = row && row.querySelector('.ai-slot .ai-reason');
        if (!reason) return null;
        return {
          url: location.href,
          reason: reason.textContent.trim(),
          // The answer is labelled as the model's, in the row's own cell.
          tagged: !!row.querySelector('.ai-slot .ai-box .ai-tag') && !!reason.closest('.ai-box'),
          when: ((row.querySelector('.ai-slot .ai-box .ai-when') || {}).textContent || '').trim(),
          prio: (row.querySelector('.ai-slot .prio') || {}).textContent || '',
          barSpin: !!document.querySelector('#ai-bar-state .ai-spin'),
          barText: (document.getElementById('ai-bar-state') || {}).textContent || '',
          enabled: !(document.querySelector('#ai-run-form button') || { disabled: true }).disabled,
          spinnersLeft: document.querySelectorAll('#cands-body .ai-wait').length,
          // Every card on the page carries a priority and a reasoning; a row
          // the answer skipped shows the not-reviewed note instead.
          // The swapped-in bar's time must already be the compact operator-tz form.
          barTimeNow: (document.querySelector('#ai-bar time.ai-at') || {}).textContent || '',
          emptyCards: Array.from(document.querySelectorAll('#cands-body .ai-box'))
            .filter(b => !(b.querySelector('.prio') || {}).textContent || !(b.querySelector('.ai-reason') || {}).textContent.trim()).length,
        };
      }, SEED_IP);
    }
    if (!done) {
      ok(false, 'the reasoning never appeared in the row (stub calls: ' + calls + ')');
    } else {
      ok(done.url === before, `finishing navigated: ${done.url}`);
      ok(done.reason === 'E2E-REASON-OK', `wrong reasoning in the row: ${JSON.stringify(done.reason)}`);
      ok(done.prio === 'high', `wrong priority badge: ${JSON.stringify(done.prio)}`);
      ok(done.tagged, 'the model\'s answer is not in its labelled AI box');
      ok(done.when.length > 0, 'the card must say when the review was fetched');
      ok(!done.barSpin && done.enabled, 'after the run the bar still spins / the button is still disabled');
      ok(done.spinnersLeft === 0, `${done.spinnersLeft} row spinner(s) left after the run`);
      ok(done.emptyCards === 0, `${done.emptyCards} empty AI card(s) after the run`);
      ok(/^\d{2}[-/]\d{2} \d{2}:\d{2}$/.test(done.barTimeNow.trim()), `right after the swap the bar time must be compact, got ${JSON.stringify(done.barTimeNow)}`);
      ok(calls === 1, `the provider was called ${calls} time(s), want 1`);

      // --- the swapped-in rows are wired: IP popover + BAN dialog ------------
      const popText = await page.evaluate(async (ip) => {
        const el = document.querySelector(`#cands-body .ipclick[data-ip="${ip}"]`);
        el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: 300, clientY: 300 }));
        await new Promise(r => setTimeout(r, 900));
        return document.getElementById('ip-popover').textContent;
      }, SEED_IP);
      ok(popText.indexOf(SEED_IP) >= 0, `after the swap the IP popover is dead: ${JSON.stringify(popText.slice(0, 60))}`);
      await page.click('#cands-body tr form.js-ban-form button');
      await sleep(300);
      const dlg = await page.evaluate(() => ({
        open: document.getElementById('ban-dialog').open,
        target: document.getElementById('ban-dialog-target').textContent,
      }));
      ok(dlg.open && dlg.target.indexOf(SEED_IP) >= 0, 'after the swap the BAN dialog does not open from the row');
      await page.click('#ban-dialog button[value="cancel"]');
      ok(page.url() === before, `the BAN dialog navigated: ${page.url()}`);

      // --- a second click with unchanged evidence calls no provider ----------
      await page.click('#ai-run-form button');
      let second = null;
      for (let i = 0; i < 30 && !second; i++) {
        await sleep(500);
        second = await page.evaluate(() => {
          const d = document.querySelector('#ai-bar .ai-delta');
          const running = !!document.querySelector('#ai-bar-state .ai-spin');
          if (running || !d) return null;
          return { reviewed: d.dataset.reviewed, kept: d.dataset.kept, text: d.textContent.trim() };
        });
      }
      ok(!!second && second.reviewed === '0' && Number(second.kept) >= 1, `an unchanged rerun must keep everything: ${JSON.stringify(second)}`);
      ok(page.url() === before, `the unchanged rerun navigated: ${page.url()}`);
      ok(calls === 1, `an unchanged rerun must not call the provider (calls ${calls})`);

      // --- a reload shows the stored result, no spinner ----------------------
      await page.reload({ waitUntil: 'networkidle2' });
      const again = await page.evaluate(() => ({
        reason: !!document.querySelector('#cands-body .ai-slot .ai-reason'),
        spinners: document.querySelectorAll('#cands-body .ai-wait').length,
        state: (document.getElementById('ai-bar') || { dataset: {} }).dataset.state,
        // The bar's time is the compact operator-tz form (MM-DD HH:MM), not the raw UTC string.
        barTime: (document.querySelector('#ai-bar time.ai-at') || {}).textContent || '',
      }));
      ok(/^\d{2}[-/]\d{2} \d{2}:\d{2}$/.test(again.barTime.trim()), `the bar time must be compact, got ${JSON.stringify(again.barTime)}`);
      ok(again.reason && again.spinners === 0, 'after a reload the stored result must show without a spinner');
      ok(again.state === 'have', `after a reload the bar must say it has an answer, got ${JSON.stringify(again.state)}`);
      ok(calls === 1, `the reload called the provider (${calls})`);
    }
  }

  // --- put the settings back -------------------------------------------------
  const restoredSave = await saveAI(false, '', '-');
  ok(restoredSave === 'ok', 'could not restore the AI advisor settings: ' + restoredSave);
  await page.goto(BASE + '/admin/advisor/?window=24', { waitUntil: 'networkidle2' });
  const restored = await page.evaluate(() => !document.getElementById('ai-run-form'));
  ok(restored, 'the model button is still offered after disabling the advisor');

  ok(jsErrors.length === 0, `page JS errors: ${jsErrors.join(' | ')}`);

  await browser.close();
  stub.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('advisor_async: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
