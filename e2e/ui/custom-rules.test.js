// The custom-rules tab: a rule is added from the template, its fields filled,
// saved, and comes back on reload with the same values; the id the save gave
// it is in the row; a bad address keeps the page on the tab with the error.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

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
    active: (document.querySelector('.settings-nav a.active, nav a.active') || {}).textContent || '',
  }));
  ok(before.add, 'the add button is missing');
  ok(before.rows === 0 && before.empty, `a fresh install shows ${before.rows} rules (empty note: ${before.empty})`);

  // Add a rule, fill it, save.
  await page.click('#cr-add');
  const added = await page.evaluate(() => ({
    rows: document.querySelectorAll('#cr-list [data-cr]').length,
    empty: !!document.getElementById('cr-empty'),
    focused: document.activeElement && document.activeElement.name,
  }));
  ok(added.rows === 1, `after add: ${added.rows} rows`);
  ok(!added.empty, 'the empty note stayed after a rule was added');
  ok(added.focused === 'cr_label', `focus after add is on ${added.focused}`);
  await page.type('#cr-list [data-cr] input[name="cr_label"]', 'ui e2e scraper');
  await page.type('#cr-list [data-cr] input[name="cr_ips"]', '203.0.113.0/24, 198.51.100.7');
  await page.type('#cr-list [data-cr] input[name="cr_ja4s"]', 'T13D1516H2_8daaf6152771_b0da82dd1658, t13d*');
  await page.type('#cr-list [data-cr] input[name="cr_countries"]', 'cn');
  await page.type('#cr-list [data-cr] input[name="cr_asns"]', 'AS4134');
  await page.type('#cr-list [data-cr] input[name="cr_ua"]', 'python-requests|scrapy');
  await page.type('#cr-list [data-cr] input[name="cr_path"]', '^/search');
  await page.type('#cr-list [data-cr] input[name="cr_memo"]', 'seen in the hunt');
  // Two boxes: the conditions, and the action -- one action on a match,
  // and beside it a rate limit with its own answer over the limit.
  const shape = await page.evaluate(() => ({
    boxes: document.querySelectorAll('#cr-list [data-cr] fieldset.cr-box').length,
    actRadios: document.querySelectorAll('#cr-list [data-cr] .cr-apply input[type=radio]').length,
    rateRadios: document.querySelectorAll('#cr-list [data-cr] .cr-rate input[type=radio]').length,
    select: !!document.querySelector('#cr-list [data-cr] select'),
    rateOff: document.querySelector('#cr-list [data-cr] .cr-rate').classList.contains('off'),
  }));
  ok(shape.boxes === 2 && shape.actRadios === 5 && shape.rateRadios === 5 && !shape.select && shape.rateOff, 'the card is not two boxes with five + five radios: ' + JSON.stringify(shape));
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
    return {
      id: v('cr_id'), label: v('cr_label'), ips: v('cr_ips'), ja4s: v('cr_ja4s'), cc: v('cr_countries'), asns: v('cr_asns'),
      ua: v('cr_ua'), path: v('cr_path'), action: v('cr_action'), rate: v('cr_rate'), rateAction: v('cr_rate_action'), enabled: v('cr_enabled'), memo: v('cr_memo'),
      checked: (row.querySelector('.cr-apply input[type=radio]:checked') || {}).value,
      rateChecked: (row.querySelector('.cr-rate input[type=radio]:checked') || {}).value,
      rows: document.querySelectorAll('#cr-list [data-cr]').length,
      hits: (row.querySelector('.cr-hits') || {}).textContent || '',
      banner: (document.querySelector('.saved, .flash, .alert-ok, [data-saved]') || {}).textContent || '',
    };
  });
  ok(!saved.missing && saved.rows === 1, `after save: ${saved.rows} rows`);
  if (!saved.missing) {
    ok(/^cr[0-9a-z]+$/.test(saved.id), `the saved rule has no id (${saved.id})`);
    ok(saved.label === 'ui e2e scraper', `label came back as ${saved.label}`);
    ok(saved.ips === '203.0.113.0/24, 198.51.100.7', `ips came back as ${saved.ips}`);
    ok(saved.ja4s === 't13d1516h2_8daaf6152771_b0da82dd1658, t13d*', `ja4s came back as ${saved.ja4s}`);
    ok(saved.cc === 'CN', `country came back as ${saved.cc}`);
    ok(saved.asns === '4134', `asn came back as ${saved.asns}`);
    ok(saved.ua === 'python-requests|scrapy' && saved.path === '^/search', `ua/path came back as ${saved.ua} / ${saved.path}`);
    ok(saved.action === 'captcha_only' && saved.rate === '30' && saved.rateAction === 'deny' && saved.enabled === '1', `action/rate/over/enabled came back as ${saved.action}/${saved.rate}/${saved.rateAction}/${saved.enabled}`);
    ok(saved.checked === 'captcha_only' && saved.rateChecked === 'deny' && saved.memo === 'seen in the hunt', 'the saved rule is not shown as it was saved: ' + JSON.stringify({ checked: saved.checked, rateChecked: saved.rateChecked, memo: saved.memo }));
    ok(saved.hits.length > 0, 'the hit count cell is empty');
  }

  // A bad address is refused: still one row, the page shows the error.
  await page.evaluate(() => { document.querySelector('#cr-list [data-cr] input[name="cr_ips"]').value = 'not-an-address'; });
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const refused = await page.evaluate(() => ({
    rows: document.querySelectorAll('#cr-list [data-cr]').length,
    ips: (document.querySelector('#cr-list [data-cr] input[name="cr_ips"]') || {}).value,
    text: document.body.innerText,
  }));
  ok(refused.rows === 1, `after a refused save: ${refused.rows} rows`);
  ok(refused.ips === '203.0.113.0/24, 198.51.100.7', `a refused save changed the stored rule (${refused.ips})`);
  ok(/not-an-address/.test(refused.text), 'the error does not name the bad value');

  // Removing the card and saving removes the rule.
  await page.click('#cr-list [data-cr] .cr-remove');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const gone = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr]').length);
  ok(gone === 0, `after removing: ${gone} rows`);

  // A draft from the hunt or the assistant: the card is there, filled and
  // focused, unsaved until the operator saves it.
  resp = await page.goto(BASE + '/admin/settings/custom-rules/?new=1&label=from%20hunt&asns=4134&ua=scrapy&action=monitor', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `draft status ${resp.status()}`);
  const draft = await page.evaluate(() => {
    const d = document.getElementById('cr-draft');
    if (!d) return { missing: true };
    const v = n => (d.querySelector('[name="' + n + '"]') || {}).value;
    return { id: v('cr_id'), label: v('cr_label'), asns: v('cr_asns'), ua: v('cr_ua'), action: v('cr_action'),
      focused: document.activeElement && document.activeElement.name, rows: document.querySelectorAll('#cr-list [data-cr]').length };
  });
  ok(!draft.missing, 'the draft card is missing');
  if (!draft.missing) {
    ok(draft.id === '' && draft.label === 'from hunt' && draft.asns === '4134' && draft.ua === 'scrapy' && draft.action === 'monitor', `draft fields: ${JSON.stringify(draft)}`);
    ok(draft.focused === 'cr_label', `focus on the draft is on ${draft.focused}`);
    ok(draft.rows === 1, `rows with a draft: ${draft.rows}`);
  }
  // Reloading the plain tab shows nothing was saved by viewing the draft.
  await page.goto(BASE + '/admin/settings/custom-rules/', { waitUntil: 'networkidle2' });
  const unsaved = await page.evaluate(() => document.querySelectorAll('#cr-list [data-cr]').length);
  ok(unsaved === 0, `viewing a draft saved ${unsaved} rule(s)`);
  // Saving the draft keeps it.
  await page.goto(BASE + '/admin/settings/custom-rules/?new=1&label=from%20hunt&asns=4134&ua=scrapy&action=monitor', { waitUntil: 'networkidle2' });
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action$="section=custom-rules"] button[type="submit"]'),
  ]);
  const kept = await page.evaluate(() => {
    const row = document.querySelector('#cr-list [data-cr]');
    return { rows: document.querySelectorAll('#cr-list [data-cr]').length, id: row ? row.querySelector('[name="cr_id"]').value : '', draft: !!document.getElementById('cr-draft') };
  });
  ok(kept.rows === 1 && /^cr[0-9a-z]+$/.test(kept.id) && !kept.draft, `after saving the draft: ${JSON.stringify(kept)}`);
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
