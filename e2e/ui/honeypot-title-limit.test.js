// A custom honeypot rule's title leads the reason of every ban the rule
// creates, and the reason keeps 80 characters of it.  The page says so where
// the operator is typing, instead of the ban cutting the title later: past the
// limit the field is red, a note under the row says why, and the save is held
// by the browser's own validation (the bubble points at the field).  Back
// under the limit, all of that goes away.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const LIST = 'honeypot_url_path';
const LIMIT = 80;
const SAVE = 'form[action*="save?section=honeypot"] button[type="submit"]:not([formaction])';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// The state of the row being typed into: the field's validity and colour,
// the note under the row, and whether the form would submit.
const readState = (page) => page.evaluate((name) => {
  const list = document.querySelector('.rule-list[data-rule-name="' + name + '"]');
  const row = list && Array.from(list.querySelectorAll('.rule-row.editing')).pop();
  const input = row && row.querySelector('input.rule-title');
  if (!input) return { err: 'no editing row with a title field' };
  const note = row.nextElementSibling;
  return {
    invalid: input.matches(':invalid'),
    message: input.validationMessage,
    border: getComputedStyle(input).borderColor,
    note: note && note.classList.contains('maxchars-err') ? note.textContent : '',
    formValid: input.form.checkValidity(),
    rows: list.querySelectorAll('.rule-row').length,
  };
}, LIST);

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  await page.goto(BASE + '/admin/settings/honeypot/', { waitUntil: 'networkidle2' });
  const added = await page.evaluate(async (name) => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="' + name + '"]');
    if (!add) return false;
    add.click();
    await new Promise(res => setTimeout(res, 80));
    return !!document.activeElement && document.activeElement.matches('.rule-row.editing input.rule-title');
  }, LIST);
  ok(added, 'adding a row must focus its title field');

  // Type to the limit: nothing to say.
  await page.keyboard.type('t'.repeat(LIMIT));
  let s = await readState(page);
  ok(!s.err, s.err || '');
  ok(s.invalid === false && s.note === '' && s.formValid === true,
    'a title at the limit must be accepted as typed: ' + JSON.stringify(s));
  const plainBorder = s.border;

  // One character past it: red field, the note, and a form that will not submit.
  await page.keyboard.type('t');
  s = await readState(page);
  ok(s.invalid === true, 'a title past the limit is not flagged: ' + JSON.stringify(s));
  ok(s.message.indexOf(String(LIMIT)) >= 0, 'the field does not say the limit: ' + s.message);
  ok(s.note === s.message && s.note !== '', 'no note under the row, or not the same words: ' + JSON.stringify(s));
  ok(s.border !== plainBorder && /220, 38, 38/.test(s.border), 'the field did not turn red: ' + s.border);
  ok(s.formValid === false, 'the form would still submit');

  // Save: held by the browser, the page stays, the field has the focus.
  const urlBefore = page.url();
  await page.click(SAVE);
  await new Promise(res => setTimeout(res, 600));
  ok(page.url() === urlBefore, 'the save went through with a title past the limit');
  const focused = await page.evaluate(() => document.activeElement && document.activeElement.matches('input.rule-title:invalid'));
  ok(focused === true, 'the held save did not point at the field');

  // Back under the limit: everything clears.
  await page.keyboard.press('Backspace');
  s = await readState(page);
  ok(s.invalid === false && s.note === '' && s.formValid === true && s.border === plainBorder,
    'the flag did not clear once the title fit again: ' + JSON.stringify(s));

  // A multi-byte title has the same room: 80 characters, not 80 bytes.
  await page.evaluate(() => { const i = document.activeElement; i.value = ''; });
  await page.keyboard.type('罠'.repeat(LIMIT));
  s = await readState(page);
  ok(s.invalid === false, 'a Japanese title at the limit is flagged: ' + JSON.stringify(s));
  await page.keyboard.type('罠');
  s = await readState(page);
  ok(s.invalid === true, 'a Japanese title one past the limit is not flagged: ' + JSON.stringify(s));

  await browser.close();
  if (fails.length) {
    console.error('FAIL honeypot-title-limit:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok honeypot-title-limit');
})().catch(e => { console.error('ERROR honeypot-title-limit: ' + (e.stack || e)); process.exit(1); });
