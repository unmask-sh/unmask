// The settings page shows a pattern's text in its box and its mode on a chip,
// and puts the chip's marker back on the value at submit.  It did that without
// looking at the box, so a marker the operator also typed there -- natural
// after reading "exact:Bot" in config.yml -- was stored twice
// ("exact:exact:Bot"), an exact match for the literal text "exact:Bot" that
// rescued nothing, and a row already doubled stayed doubled on every save.
// This drives the UA allowlist through a real browser and reads back what the
// save stored:
//   - a marker typed on top of the chip's is stored once;
//   - a box left holding only a marker is dropped like a blank row;
//   - a doubled value posted by a page without the fix is stored once (the
//     server keeps one marker on every pattern list).
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const LIST = 'white_extra';
const TEXT = 'ExampleBot/1.0';
const SAVE = 'form[action*="save?section=ua-filter"] button[type="submit"]';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// Every row of the list as the reloaded page shows it: the box (the page has
// stripped the stored marker into the chip), the chip's mode, and the
// confirmed row's text without its mode badge.
const readRows = (page) => page.evaluate((name) => {
  const list = document.querySelector('.rule-list[data-rule-name="' + name + '"]');
  if (!list) return null;
  return Array.from(list.querySelectorAll('.rule-row')).map(row => {
    const input = row.querySelector('input[name="' + name + '"]');
    const chip = row.querySelector('.rule-pat-mode');
    const view = row.querySelector('.rule-view .pat');
    let text = '';
    if (view) {
      const c = view.cloneNode(true);
      c.querySelectorAll('.pat-lit').forEach(e => e.remove());
      text = c.textContent.trim();
    }
    return { val: input ? input.value : null, mode: chip ? chip.dataset.mode : null, text };
  });
}, LIST);

// Add a row, turn its chip to exact, and type into the box the way an
// operator does.
const addExactRow = async (page, typed) => {
  const r = await page.evaluate(async (name) => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="' + name + '"]');
    if (!add) return { err: 'no add button' };
    add.click();
    await new Promise(res => setTimeout(res, 80));
    let input = null;
    document.querySelectorAll('.rule-row.editing input[name="' + name + '"]').forEach(i => { input = i; });
    if (!input) return { err: 'no input on the new row' };
    const chip = input.parentElement.querySelector('.rule-pat-mode');
    if (!chip) return { err: 'the new row has no mode chip' };
    for (let i = 0; i < 4 && chip.dataset.mode !== 'exact'; i++) chip.click();
    input.focus();
    return { mode: chip.dataset.mode };
  }, LIST);
  ok(!r.err, 'add row: ' + (r.err || ''));
  ok(r.mode === 'exact', 'the new row\'s chip must reach exact, got ' + r.mode);
  await page.keyboard.type(typed);
};

const save = (page) => Promise.all([
  page.waitForNavigation({ waitUntil: 'networkidle2' }),
  page.click(SAVE),
]);

const ours = (rows) => rows.filter(r => (r.val || '').endsWith(TEXT) || r.text.endsWith(TEXT));

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

  await page.goto(BASE + '/admin/settings/ua-filter/', { waitUntil: 'networkidle2' });
  const before = await readRows(page);
  ok(before !== null, 'the UA tab has no ' + LIST + ' list');
  const base = before ? before.length : 0;

  // 1. A marker typed on top of the chip's, and a box holding only a marker.
  await addExactRow(page, 'exact:' + TEXT);
  await addExactRow(page, 'exact:');
  await save(page);
  let rows = (await readRows(page)) || [];
  let mine = ours(rows);
  ok(rows.length === base + 1, 'the marker-only row must be dropped: want ' + (base + 1) + ' rows, got ' + JSON.stringify(rows));
  ok(mine.length === 1 && mine[0].val === TEXT && mine[0].mode === 'exact' && mine[0].text === TEXT,
    'a typed marker must be stored once: ' + JSON.stringify(mine));
  ok(!rows.some(r => /^(contains|exact|subdomain):/.test(r.val || '')),
    'no box may still show a marker once the page has read it: ' + JSON.stringify(rows));

  // 2. A doubled value posted by a page without the fix -- no chip on the row,
  //    so the submit hook leaves the value as it is -- is stored once.
  const doubled = await page.evaluate((name, text) => {
    const list = document.querySelector('.rule-list[data-rule-name="' + name + '"]');
    for (const row of list.querySelectorAll('.rule-row')) {
      const input = row.querySelector('input[name="' + name + '"]');
      if (input && input.value === text) {
        const chip = row.querySelector('.rule-pat-mode');
        if (chip) chip.remove();
        input.value = 'exact:exact:' + text;
        return true;
      }
    }
    return false;
  }, LIST, TEXT);
  ok(doubled, 'the stored row must be found to post it doubled');
  await save(page);
  rows = (await readRows(page)) || [];
  mine = ours(rows);
  ok(mine.length === 1 && mine[0].val === TEXT && mine[0].mode === 'exact',
    'a doubled value must be stored with one marker: ' + JSON.stringify(mine));

  // Put the instance back the way run.sh seeded it: drop our row and save.
  const removed = await page.evaluate((name, text) => {
    let hit = false;
    document.querySelectorAll('.rule-list[data-rule-name="' + name + '"] .rule-row').forEach(row => {
      const i = row.querySelector('input[name="' + name + '"]');
      if (i && i.value === text) { row.remove(); hit = true; }
    });
    return hit;
  }, LIST, TEXT);
  ok(removed, 'cleanup: the added row must be found for removal');
  await save(page);
  rows = (await readRows(page)) || [];
  ok(rows.length === base, 'cleanup: the list must be back to ' + base + ' rows, got ' + JSON.stringify(rows));

  await browser.close();
  if (fails.length) {
    console.error('FAIL pattern-marker-once:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok pattern-marker-once');
})().catch(e => { console.error('ERROR pattern-marker-once: ' + (e.stack || e)); process.exit(1); });
