// Browser-level check of the redesigned protected-paths tab (mode == action).
// Against a real running admin (real templates + the rule-list JS), verifies:
//   - the tab renders and folds preset + custom into ONE card with both badges,
//   - each preset carries a mode dropdown (protected_preset_mode__<id>) whose
//     default is the strongest chain (pow_then_captcha),
//   - the removed confusing controls are gone (no protected_default_action
//     dropdown, no rate-limit "連動 / linkage" copy),
//   - a newly added custom row defaults to pow_then_captcha and its mode pill
//     tracks the SELECT (the syncRowPills [name$="_mode"] fix) -- so hiding the
//     select while not editing never loses the value.
//
// Driven by run.sh (throwaway admin). Env: UI_E2E_BASE, UI_E2E_USER,
// UI_E2E_PASS, CHROME_BIN.
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
    defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();

  // ---- login ----
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // ---- the protected tab renders ----
  const resp = await page.goto(BASE + '/admin/settings/protected/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/protected/ status ${resp.status()}`);

  const view = await page.evaluate(() => {
    const form = document.querySelector('form[action*="save?section=protected"]');
    const scope = form || document;
    // Preset mode dropdown for the "unmask" preset.
    const presetSel = scope.querySelector('select[name="protected_preset_mode__unmask"]');
    return {
      cards: scope.querySelectorAll('.bcd-card').length,
      presetBadges: scope.querySelectorAll('.card-badge.preset').length,
      customBadges: scope.querySelectorAll('.card-badge.custom').length,
      presetSelVal: presetSel ? presetSel.value : null,
      presetSelOpts: presetSel ? Array.from(presetSel.options).map(o => o.value) : [],
      hasDefaultAction: !!scope.querySelector('[name="protected_default_action"]'),
      hasOldActionSel: !!scope.querySelector('select[name="protected_action"]'),
      // The confusing "linkage to rate-limit default" copy must be gone.
      linkageCopy: (scope.textContent || '').includes('連動') ||
                   (scope.textContent || '').toLowerCase().includes('rate-limit default'),
    };
  });
  ok(view.cards === 1, `protected tab should be ONE card, found ${view.cards}`);
  ok(view.presetBadges >= 1 && view.customBadges >= 1,
     `preset+custom badges should coexist in the card (preset=${view.presetBadges} custom=${view.customBadges})`);
  ok(view.presetSelVal === 'pow_then_captcha',
     `unmask preset mode default should be pow_then_captcha, got ${JSON.stringify(view.presetSelVal)}`);
  ok(JSON.stringify(view.presetSelOpts) === JSON.stringify(['pow_then_captcha', 'pow', 'captcha']),
     `preset mode options unexpected: ${JSON.stringify(view.presetSelOpts)}`);
  ok(!view.hasDefaultAction, 'the removed protected_default_action dropdown is still present');
  ok(!view.hasOldActionSel, 'the removed per-row protected_action chain dropdown is still present');
  ok(!view.linkageCopy, 'the confusing rate-limit "連動 / linkage" copy is still shown');

  // ---- a newly added custom row defaults to pow_then_captcha ----
  await page.click('.rule-add-bottom[data-target-list="protected_path"]');
  const added = await page.evaluate(() => {
    const list = document.querySelector('.rule-list[data-rule-name="protected_path"]');
    const rows = list.querySelectorAll('.rule-row');
    const row = rows[rows.length - 1];
    const sel = row.querySelector('select[name="protected_mode"]');
    return { hasSel: !!sel, val: sel ? sel.value : null };
  });
  ok(added.hasSel, 'a new protected row has no mode select');
  ok(added.val === 'pow_then_captcha',
     `a new protected row should default to pow_then_captcha, got ${JSON.stringify(added.val)}`);

  // ---- the mode pill tracks the SELECT on confirm (syncRowPills reads
  //      [name$="_mode"], so the value survives the select being hidden) ----
  const piled = await page.evaluate(() => {
    const list = document.querySelector('.rule-list[data-rule-name="protected_path"]');
    const rows = list.querySelectorAll('.rule-row');
    const row = rows[rows.length - 1];
    row.querySelector('select[name="protected_mode"]').value = 'captcha';
    row.querySelector('input[name="protected_path"]').value = '^/secret/';
    // Confirm the row (✓): the save handler rebuilds the summary pills from the
    // row's current inputs -- this is the path a real edit takes.
    row.querySelector('.rule-save').click();
    const pill = row.querySelector('[data-pill="mode"]');
    return pill ? pill.textContent.trim() : null;
  });
  ok(piled === 'captcha',
     `mode pill should track the select value on confirm (want "captcha"), got ${JSON.stringify(piled)}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('protected-mode: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
