// The custom-rules tab: a rule is a name, condition lines (kind + values +
// memo; all must hold), one action and an optional rate limit with its own
// over-limit answer.  A new rule is made from the page's template, lines
// are added and removed, the rule is saved and comes back on reload with
// the same values; a bad line keeps the page on the tab with the error
// naming the rule and the line; a draft from the hunt or the assistant
// arrives filled in and unsaved.
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
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  let resp = await page.goto(BASE + '/admin/settings/custom-rules/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/custom-rules/ status ${resp.status()}`);
  const before = await page.evaluate(() => ({
    rows: document.querySelectorAll('#cr-list [data-cr]').length,
    empty: !!document.getElementById('cr-empty'),
    add: !!document.getElementById('cr-add'),
    addText: (document.getElementById('cr-add') || {}).textContent || '',
  }));
  ok(before.add && /新規ルール|New rule/.test(before.addText), 'the new-rule button is missing or misnamed: ' + before.addText);
  ok(before.rows === 0 && before.empty, `a fresh install shows ${before.rows} rules (empty note: ${before.empty})`);

  // A new rule: one empty line to start, keyed new1; fill the name and the
  // first line (JA4), add an ASN line and a UA line, remove a spare line.
  await page.click('#cr-add');
  const added = await page.evaluate(() => {
    const card = document.querySelector('#cr-list [data-cr]');
    return {
      rows: document.querySelectorAll('#cr-list [data-cr]').length,
      key: card ? card.dataset.key : '', keyField: card ? card.querySelector('[name="cr_key"]').value : '',
      lines: card ? card.querySelectorAll('[data-cond]').length : 0,
      lineName: card ? (card.querySelector('[data-cond] select') || {}).name : '',
      radioName: card ? (card.querySelector('.cr-apply input[type=radio]') || {}).name : '',
      boxes: card ? card.querySelectorAll('fieldset.cr-box').length : 0,
      focused: document.activeElement && document.activeElement.name,
      empty: !!document.getElementById('cr-empty'),
    };
  });
  ok(added.rows === 1 && !added.empty, `after the new rule: ${added.rows} rows, empty note ${added.empty}`);
  ok(added.key === 'new1' && added.keyField === 'new1' && added.lineName === 'cc_new1_kind' && added.radioName === 'cr_act_new1', 'the new card is not keyed new1: ' + JSON.stringify(added));
  ok(added.lines === 1 && added.boxes === 2 && added.focused === 'cr_label', 'the new card is not one line in two boxes with the name focused: ' + JSON.stringify(added));
  await page.type('#cr-list [data-cr] input[name="cr_label"]', 'ui e2e scraper');
  await page.select('#cr-list [data-cr] [data-cond]:nth-child(1) select', 'ja4');
  const ph = await page.evaluate(() => document.querySelector('#cr-list [data-cr] [data-cond]:nth-child(1) .cc-values').placeholder);
  ok(/t13d/.test(ph), 'the values placeholder did not follow the kind: ' + ph);
  await page.type('#cr-list [data-cr] [data-cond]:nth-child(1) .cc-values', 'T13D1516H2_8daaf6152771_b0da82dd1658, t13d*');
  await page.type('#cr-list [data-cr] [data-cond]:nth-child(1) .cc-memo', 'seen in the hunt');
  await page.click('#cr-list [data-cr] .cc-add');
  await page.select('#cr-list [data-cr] [data-cond]:nth-child(2) select', 'asn');
  await page.type('#cr-list [data-cr] [data-cond]:nth-child(2) .cc-values', 'AS4134, 16509');
  await page.click('#cr-list [data-cr] .cc-add');
  await page.select('#cr-list [data-cr] [data-cond]:nth-child(3) select', 'ua');
  await page.type('#cr-list [data-cr] [data-cond]:nth-child(3) .cc-values', 'python-requests|scrapy');
  await page.click('#cr-list [data-cr] .cc-add');
  const four = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr] [data-cond]').length);
  ok(four === 4, `after three adds: ${four} lines`);
  await page.click('#cr-list [data-cr] [data-cond]:nth-child(4) .cc-del');
  const three = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr] [data-cond]').length);
  ok(three === 3, `after removing the spare line: ${three} lines`);

  // One action on a match; beside it the rate limit with its own answer.
  const shape = await page.evaluate(() => ({
    actRadios: document.querySelectorAll('#cr-list [data-cr] .cr-apply input[type=radio]').length,
    rateRadios: document.querySelectorAll('#cr-list [data-cr] .cr-rate input[type=radio]').length,
    rateOff: document.querySelector('#cr-list [data-cr] .cr-rate').classList.contains('off'),
  }));
  ok(shape.actRadios === 5 && shape.rateRadios === 5 && shape.rateOff, 'the action box is not five + five radios: ' + JSON.stringify(shape));
  await page.click('#cr-list [data-cr] .cr-apply input[type=radio][value="captcha_only"]');
  await page.type('#cr-list [data-cr] input[name="cr_rate"]', '30');
  await page.click('#cr-list [data-cr] .cr-rate input[type=radio][value="deny"]');
  const chosen = await page.evaluate(() => ({ act: document.querySelector('#cr-list [data-cr] input[name="cr_action"]').value, ract: document.querySelector('#cr-list [data-cr] input[name="cr_rate_action"]').value, rateOff: document.querySelector('#cr-list [data-cr] .cr-rate').classList.contains('off') }));
  ok(chosen.act === 'captcha_only' && chosen.ract === 'deny' && !chosen.rateOff, 'the radios did not set the hidden fields: ' + JSON.stringify(chosen));
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  ok(page.url().indexOf('/admin/settings/custom-rules/') >= 0, `after save the page is ${page.url()}`);
  const saved = await page.evaluate(() => {
    const row = document.querySelector('#cr-list [data-cr]');
    if (!row) return { missing: true };
    const v = n => (row.querySelector('[name="' + n + '"]') || {}).value;
    const lines = Array.from(row.querySelectorAll('[data-cond]')).map(l => ({ kind: l.querySelector('select').value, values: l.querySelector('.cc-values').value, memo: l.querySelector('.cc-memo').value }));
    return {
      id: v('cr_id'), key: v('cr_key'), label: v('cr_label'), action: v('cr_action'), rate: v('cr_rate'), rateAction: v('cr_rate_action'), enabled: v('cr_enabled'),
      lines, rows: document.querySelectorAll('#cr-list [data-cr]').length,
      checked: (row.querySelector('.cr-apply input[type=radio]:checked') || {}).value,
      rateChecked: (row.querySelector('.cr-rate input[type=radio]:checked') || {}).value,
      hits: (row.querySelector('.cr-hits') || {}).textContent || '',
    };
  });
  ok(!saved.missing && saved.rows === 1, `after save: ${saved.rows} rows`);
  if (!saved.missing) {
    ok(/^cr[0-9a-z]+$/.test(saved.id) && saved.key === saved.id, `the saved rule has no id or its key differs (${saved.id} / ${saved.key})`);
    ok(saved.label === 'ui e2e scraper', `label came back as ${saved.label}`);
    ok(saved.lines.length === 3 && saved.lines[0].kind === 'ja4' && saved.lines[0].values === 't13d1516h2_8daaf6152771_b0da82dd1658, t13d*' && saved.lines[0].memo === 'seen in the hunt' &&
       saved.lines[1].kind === 'asn' && saved.lines[1].values === '4134, 16509' && saved.lines[2].kind === 'ua' && saved.lines[2].values === 'python-requests|scrapy',
       'the lines came back differently: ' + JSON.stringify(saved.lines));
    ok(saved.action === 'captcha_only' && saved.rate === '30' && saved.rateAction === 'deny' && saved.enabled === '1', `action/rate/over/enabled came back as ${saved.action}/${saved.rate}/${saved.rateAction}/${saved.enabled}`);
    ok(saved.checked === 'captcha_only' && saved.rateChecked === 'deny', 'the radios do not show the saved choices: ' + JSON.stringify({ checked: saved.checked, rateChecked: saved.rateChecked }));
    ok(saved.hits.length > 0, 'the hit count cell is empty');
  }

  // A bad line is refused: still one rule, the error names the rule and
  // the line, the stored values are untouched.
  await page.evaluate(() => { document.querySelector('#cr-list [data-cr] [data-cond]:nth-child(1) .cc-values').value = 'not a ja4!'; });
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const refused = await page.evaluate(() => ({
    rows: document.querySelectorAll('#cr-list [data-cr]').length,
    values: (document.querySelector('#cr-list [data-cr] [data-cond]:nth-child(1) .cc-values') || {}).value,
    text: document.body.innerText,
    banner: (document.querySelector('.banner.bad') || {}).textContent || '',
  }));
  ok(refused.rows === 1, `after a refused save: ${refused.rows} rows`);
  ok(refused.values === 't13d1516h2_8daaf6152771_b0da82dd1658, t13d*', `a refused save changed the stored rule (${refused.values})`);
  // (a list field splits on spaces too, so the value named is the first
  // token that fails: "ja4!")
  ok(/rule 1 \(ui e2e scraper\): condition 1 \(ja4\)/.test(refused.banner) && /"ja4!" is not a JA4 fingerprint/.test(refused.banner), 'the error does not name the rule, the line and the bad value: ' + JSON.stringify(refused.banner));

  // Removing the card and saving removes the rule.
  await page.click('#cr-list [data-cr] .cr-remove');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const gone = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr]').length);
  ok(gone === 0, `after removing: ${gone} rows`);

  // A draft from the hunt or the assistant: the lines are there, filled and
  // keyed "draft", the name focused, unsaved until the operator saves it.
  const draftURL = '/admin/settings/custom-rules/?new=1&label=hunt%3A%20AS4134&c=asn%3A4134&c=ua%3Ascrapy&action=monitor';
  resp = await page.goto(BASE + draftURL, { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `draft status ${resp.status()}`);
  const draft = await page.evaluate(() => {
    const d = document.getElementById('cr-draft');
    if (!d) return { missing: true };
    const v = n => (d.querySelector('[name="' + n + '"]') || {}).value;
    const lines = Array.from(d.querySelectorAll('[data-cond]')).map(l => ({ kind: l.querySelector('select').value, values: l.querySelector('.cc-values').value, name: l.querySelector('select').name }));
    return { id: v('cr_id'), key: v('cr_key'), label: v('cr_label'), action: v('cr_action'), lines, focused: document.activeElement && document.activeElement.name, rows: document.querySelectorAll('#cr-list [data-cr]').length };
  });
  ok(!draft.missing, 'the draft card is missing');
  if (!draft.missing) {
    ok(draft.id === '' && draft.key === 'draft' && draft.label === 'hunt: AS4134' && draft.action === 'monitor', `draft fields: ${JSON.stringify(draft)}`);
    ok(draft.lines.length === 2 && draft.lines[0].kind === 'asn' && draft.lines[0].values === '4134' && draft.lines[1].kind === 'ua' && draft.lines[1].values === 'scrapy' && draft.lines[0].name === 'cc_draft_kind', 'the draft lines: ' + JSON.stringify(draft.lines));
    ok(draft.focused === 'cr_label' && draft.rows === 1, `focus / rows on the draft: ${draft.focused} / ${draft.rows}`);
  }
  await page.goto(BASE + '/admin/settings/custom-rules/', { waitUntil: 'networkidle2' });
  const unsaved = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr]').length);
  ok(unsaved === 0, `viewing a draft saved ${unsaved} rule(s)`);
  // Saving the draft keeps it, and a draft line removed before saving stays removed.
  await page.goto(BASE + draftURL, { waitUntil: 'networkidle2' });
  await page.click('#cr-draft [data-cond]:nth-child(2) .cc-del');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const kept = await page.evaluate(() => {
    const row = document.querySelector('#cr-list [data-cr]');
    return { rows: document.querySelectorAll('#cr-list [data-cr]').length, id: row ? row.querySelector('[name="cr_id"]').value : '', lines: row ? row.querySelectorAll('[data-cond]').length : 0, draft: !!document.getElementById('cr-draft') };
  });
  ok(kept.rows === 1 && /^cr[0-9a-z]+$/.test(kept.id) && kept.lines === 1 && !kept.draft, `after saving the draft: ${JSON.stringify(kept)}`);
  await page.click('#cr-list [data-cr] .cr-remove');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('custom-rules: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
