// A custom row on the JA4 verdicts tab carries five controls -- a name, the
// pattern, the verdict label and two pickers -- and on one line the pattern,
// the only field that has to hold a whole fingerprint, was the one squeezed.
// An open row takes two lines instead: name and pattern on the first, the
// verdict and both pickers on the second with the row's buttons at the far
// right, whatever the width of the window.  Confirming the row (the check
// mark) writes every edited value back into the folded row, the verdict label
// and the block / observe / allow pill included: those two used to vanish
// until the page was reloaded.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN,
// UI_E2E_SHOT_DIR (optional: where to drop screenshots of the row).
const puppeteer = require('puppeteer-core');
const path = require('path');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOTS = process.env.UI_E2E_SHOT_DIR || '';
const LIST = 'ja4_extra';
const ROW = '.rule-list[data-rule-name="' + LIST + '"] .rule-row.editing';
// A whole fingerprint, the value the pattern field exists to hold.
const JA4 = 't13d1516h2_8daaf6152771_b0da82dd1658';
const VERDICT = 'chrome_fake_h1';
const TITLE = 'Fake Chrome over h1';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

// Where every control of the open row sits.  Lines are told apart by vertical
// overlap, widths by their share of the row: nothing here depends on the
// font the browser draws with.
const measure = (page) => page.evaluate((sel) => {
  const rows = document.querySelectorAll(sel);
  const row = rows[rows.length - 1];
  if (!row) return { err: 'no open row' };
  const q = (s) => row.querySelector(s);
  const box = (el) => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, width: r.width };
  };
  const pat = q('input.rule-pat');
  return {
    row: box(row),
    title: box(q('input.rule-title')),
    pat: box(pat),
    patFits: pat ? pat.scrollWidth <= pat.clientWidth : null,
    verd: box(q('input.rule-verd')),
    kind: box(q('select.rule-action')),
    chain: box(q('select.extra-action-sel')),
    save: box(q('button.rule-save')),
    add: box(q('button.rule-add')),
    overflow: row.scrollWidth > row.clientWidth,
  };
}, ROW);

const sameLine = (a, b) => a && b && a.bottom > b.top && b.bottom > a.top;

function checkLayout(m, where) {
  if (m.err) { ok(false, where + ': ' + m.err); return; }
  for (const k of ['title', 'pat', 'verd', 'kind', 'chain', 'save', 'add']) {
    ok(m[k], where + ': the open row has no ' + k);
  }
  if (!m.title || !m.pat || !m.verd || !m.kind || !m.chain || !m.save || !m.add) return;
  ok(sameLine(m.title, m.pat), where + ': name and pattern should share the first line');
  ok(m.verd.top >= m.pat.bottom, where + ': the verdict should start a line below the pattern');
  ok(sameLine(m.verd, m.kind) && sameLine(m.verd, m.chain) && sameLine(m.verd, m.save) && sameLine(m.verd, m.add),
     where + ': verdict, both pickers and the buttons should share the second line');
  ok(m.pat.width >= m.row.width / 2,
     where + ': the pattern field should take at least half the row, has ' + Math.round(m.pat.width) + ' of ' + Math.round(m.row.width));
  ok(m.save.left > m.chain.right && m.row.right - m.add.right < m.row.width / 20,
     where + ': the buttons should sit at the right end of the second line');
  ok(m.patFits === true, where + ': a whole fingerprint should fit the pattern field without scrolling');
  ok(!m.overflow, where + ': the open row overflows horizontally');
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  let pageErrors = 0;
  page.on('pageerror', () => { pageErrors++; });
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/settings/ja4-verdicts/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, 'ja4-verdicts: status ' + resp.status());

  // A new row opens in edit mode with the focus on its name.
  const added = await page.evaluate(async (name) => {
    const add = document.querySelector('.rule-add-bottom[data-target-list="' + name + '"]');
    if (!add) return false;
    add.click();
    await new Promise(res => setTimeout(res, 80));
    return !!document.activeElement && document.activeElement.matches('.rule-row.editing input.rule-title');
  }, LIST);
  ok(added, 'adding a row must focus its name field');
  if (!added) {
    await browser.close();
    console.error('FAIL ja4-edit-row:\n  ' + fails.join('\n  '));
    process.exit(1);
  }

  // Fill the row the way an operator does: type into each field, pick from
  // each picker.  The pattern goes in first so the fit is measured with a
  // real fingerprint in the box.
  await page.keyboard.type(TITLE);
  await page.focus(ROW + ' input.rule-pat');
  await page.keyboard.type(JA4);
  await page.focus(ROW + ' input.rule-verd');
  await page.keyboard.type(VERDICT);
  await page.select(ROW + ' select.rule-action', 'ok');
  await page.select(ROW + ' select.extra-action-sel', 'deny');

  checkLayout(await measure(page), 'at 1360px');
  if (SHOTS) {
    try { const h = await page.$(ROW); if (h) await h.screenshot({ path: path.join(SHOTS, 'ja4-edit-row-open-1360.png') }); } catch (e) {}
  }
  // The two lines are the row's shape, not a consequence of a narrow window.
  await page.setViewport({ width: 1920, height: 900 });
  await new Promise(res => setTimeout(res, 150));
  checkLayout(await measure(page), 'at 1920px');
  if (SHOTS) {
    try { const h = await page.$(ROW); if (h) await h.screenshot({ path: path.join(SHOTS, 'ja4-edit-row-open-1920.png') }); } catch (e) {}
  }
  await page.setViewport({ width: 1360, height: 900 });
  await new Promise(res => setTimeout(res, 150));

  // Confirm: the folded row must show every value just entered.
  const kindLabel = await page.$eval(ROW + ' select.rule-action', (s) => s.options[s.selectedIndex].textContent.trim());
  await page.click(ROW + ' button.rule-save');
  await new Promise(res => setTimeout(res, 100));
  const readFolded = () => page.evaluate((name, ja4) => {
    const list = document.querySelector('.rule-list[data-rule-name="' + name + '"]');
    const row = Array.from(list.querySelectorAll('.rule-row')).find((r) => {
      const i = r.querySelector('input.rule-pat');
      return i && i.value === ja4;
    });
    if (!row) return { err: 'the confirmed row is gone' };
    const pat = row.querySelector('.rule-view .pat');
    const kind = pat.querySelector('.action-pill:not([data-pill])');
    const chain = pat.querySelector('.action-pill[data-pill="action"]');
    const verdict = pat.querySelector('.verdict');
    return {
      editing: row.classList.contains('editing'),
      title: row.querySelector('.rule-view .ttl').textContent.trim(),
      text: pat.textContent.replace(/\s+/g, ' ').trim(),
      verdict: verdict ? verdict.textContent.trim() : null,
      kind: kind ? { text: kind.textContent.trim(), cls: kind.className } : null,
      chain: chain ? chain.textContent.trim() : null,
      // The verdict and the pill come after the pattern, in that order.
      order: verdict && kind ? (pat.compareDocumentPosition(verdict) && (verdict.compareDocumentPosition(kind) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0) : null,
    };
  }, LIST, JA4);
  let f = await readFolded();
  ok(!f.err, f.err || '');
  if (!f.err) {
    ok(f.editing === false, 'the check mark did not fold the row');
    ok(f.title === TITLE, 'the folded row should show the name, shows ' + JSON.stringify(f.title));
    ok(f.text.indexOf(JA4) === 0, 'the folded row should lead with the pattern, shows ' + JSON.stringify(f.text));
    ok(f.verdict === VERDICT, 'the folded row should show the verdict label, shows ' + JSON.stringify(f.verdict));
    ok(f.text.indexOf('→') > 0, 'the folded row should read pattern → verdict, shows ' + JSON.stringify(f.text));
    ok(f.kind && f.kind.text === kindLabel && /\baction-ok\b/.test(f.kind.cls),
       'the folded row should carry the picked ' + JSON.stringify(kindLabel) + ' pill, has ' + JSON.stringify(f.kind));
    ok(f.chain === 'deny', 'the folded row should carry the picked chain, has ' + JSON.stringify(f.chain));
    ok(f.order === true, 'verdict then pill, after the pattern');
  }
  if (SHOTS) {
    try {
      const h = await page.$('.rule-list[data-rule-name="' + LIST + '"]');
      if (h) await h.screenshot({ path: path.join(SHOTS, 'ja4-edit-row-folded.png') });
    } catch (e) {}
  }

  // Open it again, change the verdict and the pill, confirm: the folded row
  // follows, and nothing is doubled.
  await page.evaluate((name, ja4) => {
    const list = document.querySelector('.rule-list[data-rule-name="' + name + '"]');
    const row = Array.from(list.querySelectorAll('.rule-row')).find((r) => {
      const i = r.querySelector('input.rule-pat');
      return i && i.value === ja4;
    });
    row.querySelector('button.rule-edit').click();
  }, LIST, JA4);
  await new Promise(res => setTimeout(res, 100));
  await page.focus(ROW + ' input.rule-verd');
  await page.keyboard.down('Control'); await page.keyboard.press('a'); await page.keyboard.up('Control');
  await page.keyboard.type('chrome_fake_h1_v2');
  await page.select(ROW + ' select.rule-action', 'suspect');
  const kindLabel2 = await page.$eval(ROW + ' select.rule-action', (s) => s.options[s.selectedIndex].textContent.trim());
  await page.click(ROW + ' button.rule-save');
  await new Promise(res => setTimeout(res, 100));
  f = await readFolded();
  ok(!f.err, f.err || '');
  if (!f.err) {
    ok(f.verdict === 'chrome_fake_h1_v2', 'the second confirm should update the verdict, shows ' + JSON.stringify(f.verdict));
    ok(f.kind && f.kind.text === kindLabel2 && /\baction-suspect\b/.test(f.kind.cls),
       'the second confirm should update the pill, has ' + JSON.stringify(f.kind));
    ok((f.text.match(/→/g) || []).length === 1, 'one arrow, not one per confirm: ' + JSON.stringify(f.text));
    ok(f.chain === 'deny', 'the chain pill should survive a confirm that did not touch it, has ' + JSON.stringify(f.chain));
  }

  ok(pageErrors === 0, pageErrors + ' JavaScript error(s) on the page');

  await browser.close();
  if (fails.length) {
    console.error('FAIL ja4-edit-row:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok ja4-edit-row');
})().catch(e => { console.error('ERROR ja4-edit-row: ' + (e.stack || e)); process.exit(1); });
