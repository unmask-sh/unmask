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

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('inherit-labels: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
