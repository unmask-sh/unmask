// Browser-level check that every settings tab whose rows inherit a default
// keeps those labels honest while the operator is still editing.
//
// A tab renders the resolved default into three places -- the "inherit" option
// on each row, the scaffold a NEW row is cloned from, and the view pill on
// rows that inherit -- all server-side.  Change the default and, without a
// refresh, all three keep naming the old value: the page contradicts the
// control the operator is looking at, and the next row added is born stating
// a chain it will not run.
//
// The scaffold is the part that keeps getting missed, because
// document.querySelectorAll does not descend into <template> content.
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

// One case per tab: the default picker, the row option, the scaffold option
// inside the <template>, and the inherit pill.
const CASES = [
  {
    tab: 'ua-filter',
    picker: 'select[name="ua_black_action"]',
    pick: 'pow_only',
    list: 'black_extra',
    option: 'select[name="black_extra_action"] option[value=""]',
    pill: '.ua-act-pill.inherit',
  },
  {
    tab: 'geo',
    picker: 'select[name="geo_default_rule_action"]',
    pick: 'captcha_only',
    list: 'geo_country',
    option: 'select[name="geo_action"] option[value=""]',
    pill: '.geo-act-pill.inherit',
  },
  {
    tab: 'asn',
    picker: 'select[name="asn_default_rule_action"]',
    pick: 'captcha_only',
    list: 'asn_number',
    option: 'select[name="asn_action"] option[value=""]',
    pill: '.asn-act-pill.inherit',
  },
];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  for (const c of CASES) {
    const resp = await page.goto(BASE + '/admin/settings/' + c.tab + '/', { waitUntil: 'networkidle2' });
    ok(resp.status() === 200, `${c.tab}: status ${resp.status()}`);

    const res = await page.evaluate((c) => {
      const d = document.querySelector(c.picker);
      if (!d) return { missing: true };
      // Make sure a real row exists: on a fresh install these lists are empty,
      // so an assertion that skips absent elements would pass without ever
      // testing the option or the pill -- which is exactly how a helper that
      // was never defined at page load went unnoticed.
      const add = document.querySelector('.rule-add-bottom[data-target-list="' + c.list + '"]');
      if (add && !document.querySelector(c.option)) add.click();
      const read = () => {
        const opt = document.querySelector(c.option);
        const tplOpt = (function(){
          for (const t of document.querySelectorAll('template.rule-row-template')) {
            const o = t.content.querySelector(c.option);
            if (o) return o;
          }
          return null;
        })();
        const pill = document.querySelector(c.pill);
        return {
          option: opt ? opt.textContent.trim() : null,
          scaffold: tplOpt ? tplOpt.textContent.trim() : null,
          pill: pill ? pill.textContent.trim() : null,
        };
      };
      const before = read();
      d.value = c.pick;
      d.dispatchEvent(new Event('change', { bubbles: true }));
      return { before, after: read() };
    }, c);

    if (res.missing) { ok(false, `${c.tab}: default picker ${c.picker} not found`); continue; }

    let checked = 0;
    for (const k of ['option', 'scaffold', 'pill']) {
      if (res.before[k] === null) continue;   // this install renders none of that kind
      checked++;
      ok(res.after[k] && res.after[k].includes(c.pick),
         `${c.tab}: the ${k} label should follow the default (${c.pick}), got ${JSON.stringify(res.after[k])}`);
    }
    // The scaffold is the one that silently rots -- fail loudly if the tab
    // stopped shipping one rather than passing by absence.
    ok(res.before.scaffold !== null, `${c.tab}: no new-row scaffold found for ${c.option}`);
    // And never let a tab pass because nothing was found to check.
    ok(checked >= 2, `${c.tab}: only ${checked} inherit label(s) present -- the check is not exercising the tab`);
  }

  // The UA-filter tab has two more pickers that inherit the blocklist default
  // without a scaffold or a pill: the crawler groups' "when stopped" picker
  // and the blocklist presets' picker.  Their inherit option names the default
  // too, and follows the tab's picker the same way.
  {
    const resp = await page.goto(BASE + '/admin/settings/ua-filter/', { waitUntil: 'networkidle2' });
    ok(resp.status() === 200, `ua-filter (group / preset pickers): status ${resp.status()}`);
    const res = await page.evaluate(() => {
      const d = document.querySelector('select[name="ua_black_action"]');
      if (!d) return { missing: true };
      const text = (sel) => { const o = document.querySelector(sel); return o ? o.textContent.trim() : null; };
      const read = () => ({
        group: text('select[name^="upstream_group_action__"] option[value="inherit"]'),
        preset: text('select[name^="black_preset_action__"] option[value="inherit"]'),
      });
      const before = read();
      d.value = 'deny';
      d.dispatchEvent(new Event('change', { bubbles: true }));
      return { before, after: read() };
    });
    if (res.missing) ok(false, 'ua-filter: default picker select[name="ua_black_action"] not found');
    else for (const k of ['group', 'preset']) {
      ok(res.before[k] !== null, `ua-filter: no ${k} inherit option found`);
      ok(res.before[k] && /\(.+\)/.test(res.before[k]),
         `ua-filter: the ${k} inherit option should name the resolved default on load, got ${JSON.stringify(res.before[k])}`);
      ok(res.after[k] && res.after[k].includes('deny'),
         `ua-filter: the ${k} inherit option should follow the default (deny), got ${JSON.stringify(res.after[k])}`);
    }
  }

  // The ja4-verdicts and honeypot tabs: their presets and custom rows inherit
  // the tab's own default, and that default may itself be unset -- it then
  // falls back to the install's default chain.  The inherit option (the
  // scaffold's included) names the resolved chain on load, follows the tab's
  // picker, and names the fallback again when the picker is set back to unset.
  for (const c of [
    {
      tab: 'ja4-verdicts',
      picker: 'select[name="ja4_default_action"]',
      list: 'ja4_extra',
      preset: 'select[name^="ja4_preset_action__"] option[value="inherit"]',
      row: 'select[name="ja4_extra_action_chain"] option[value="inherit"]',
    },
    {
      tab: 'honeypot',
      picker: 'select[name="honeypot_default_action"]',
      list: 'honeypot_url_path',
      preset: 'select[name^="honeypot_preset_action__"] option[value="inherit"]',
      row: 'select[name="honeypot_url_action"] option[value="inherit"]',
    },
  ]) {
    const resp = await page.goto(BASE + '/admin/settings/' + c.tab + '/', { waitUntil: 'networkidle2' });
    ok(resp.status() === 200, `${c.tab}: status ${resp.status()}`);
    const res = await page.evaluate((c) => {
      const d = document.querySelector(c.picker);
      if (!d) return { missing: true };
      // A real row, so the row's own option is exercised and not only the scaffold.
      const add = document.querySelector('.rule-add-bottom[data-target-list="' + c.list + '"]');
      if (add && !document.querySelector(c.row)) add.click();
      const text = (sel) => { const o = document.querySelector(sel); return o ? o.textContent.trim() : null; };
      const scaffold = (sel) => {
        for (const t of document.querySelectorAll('template.rule-row-template')) {
          const o = t.content.querySelector(sel);
          if (o) return o.textContent.trim();
        }
        return null;
      };
      const read = () => ({ preset: text(c.preset), row: text(c.row), scaffold: scaffold(c.row) });
      const before = read();
      d.value = 'deny';
      d.dispatchEvent(new Event('change', { bubbles: true }));
      const after = read();
      d.value = '';
      d.dispatchEvent(new Event('change', { bubbles: true }));
      return { before, after, unset: read() };
    }, c);
    if (res.missing) { ok(false, `${c.tab}: default picker ${c.picker} not found`); continue; }
    for (const k of ['preset', 'row', 'scaffold']) {
      ok(res.before[k] !== null, `${c.tab}: no ${k} inherit option found`);
      ok(res.before[k] && /\(.+\)/.test(res.before[k]),
         `${c.tab}: the ${k} inherit option should name the resolved default on load, got ${JSON.stringify(res.before[k])}`);
      ok(res.after[k] && res.after[k].includes('deny'),
         `${c.tab}: the ${k} inherit option should follow the default (deny), got ${JSON.stringify(res.after[k])}`);
      ok(res.unset[k] && /\(.+\)/.test(res.unset[k]) && !res.unset[k].includes('deny'),
         `${c.tab}: with the default unset the ${k} inherit option should name the install's chain, got ${JSON.stringify(res.unset[k])}`);
    }
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('inherit-labels: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
