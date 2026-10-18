// The UA tab's crawler card sets each group to pass / normal checks / stop,
// and each crawler in it to follow its group or take a mode of its own in the
// group's Detail dialog.  This drives the seo group through a real browser:
//   - the bulk buttons set only the rows the search leaves showing;
//   - confirm keeps the rows, Escape puts them back;
//   - the group row counts the crawlers set on their own, and shows the chain
//     picker once one of them is stopped;
//   - a page save stores exactly those crawlers, and the reloaded page shows
//     them again;
//   - switching the group renames "follow the group (...)" on every row;
//   - setting them back to follow the group leaves nothing in the config.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN,
// UI_E2E_CONFIG (the instance's config.yml, read back after each save).
const fs = require('fs');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const CONFIG = process.env.UI_E2E_CONFIG || '';
const SAVE = 'form[action*="save?section=ua-filter"] button[type="submit"]';
const CAT = 'seo';
const MODAL = '.upstream-modal[data-cat="' + CAT + '"]';
const GROUP = '.upstream-group[data-cat="' + CAT + '"]';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

const save = (page) => Promise.all([
  page.waitForNavigation({ waitUntil: 'networkidle2' }),
  page.click(SAVE),
]);

// The rows' own settings, keyed by pattern, plus what the group row shows.
const readGroup = (page) => page.evaluate((modalSel, groupSel) => {
  const modal = document.querySelector(modalSel);
  const grp = document.querySelector(groupSel);
  if (!modal || !grp) return null;
  const own = {};
  modal.querySelectorAll('.upstream-row').forEach(r => {
    own[r.dataset.pattern] = r.querySelector('.upstream-own-sel').value;
  });
  const oc = grp.querySelector('.upstream-own-count');
  const aw = grp.querySelector('.upstream-action-wrap');
  const follow = modal.querySelector('.upstream-row[data-pattern="rogerbot"] option[value=""]');
  return {
    own,
    ownCount: oc && !oc.hidden ? oc.querySelector('.upstream-own-n').textContent : '',
    actionShown: !!(aw && !aw.hidden),
    action: grp.querySelector('.upstream-action-sel').value,
    follow: follow ? follow.textContent : '',
    labels: ['white', 'none', 'black'].reduce((a, m) => {
      a[m] = (grp.querySelector('.mode-opt.mode-' + m + ' span') || {}).textContent || '';
      return a;
    }, {}),
    visible: Array.from(modal.querySelectorAll('.upstream-row:not(.hidden)')).map(r => r.dataset.pattern),
  };
}, MODAL, GROUP);

const openDetail = async (page) => {
  await page.click(GROUP + ' .upstream-detail-btn');
  await page.waitForFunction(sel => document.querySelector(sel).style.display === 'flex', {}, MODAL);
};

// The crawlers set on their own as config.yml stores them.
const storedModes = () => {
  if (!CONFIG) return null;
  const text = fs.readFileSync(CONFIG, 'utf8');
  const m = text.match(/\n(\s*)upstream_pattern_mode:\n((?:\1\s+.*\n)*)/);
  if (!m) return {};
  const out = {};
  m[2].split('\n').forEach(line => {
    const kv = line.trim().match(/^"?(.*?)"?:\s*(\S+)$/);
    if (kv) out[kv[1].replace(/\\\\/g, '\\')] = kv[2];
  });
  return out;
};

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

  let g = await readGroup(page);
  ok(g !== null, 'the UA tab has no ' + CAT + ' group with a Detail dialog');
  if (!g) throw new Error(fails.join('; '));
  ok(Object.values(g.own).every(v => v === ''), 'out of the box every seo crawler follows its group');
  ok(g.ownCount === '' && !g.actionShown, 'nothing set on its own: no count and no chain picker');
  ok(g.follow.indexOf(g.labels.white) >= 0, 'rows must name what following resolves to: ' + g.follow);

  // 1. The bulk buttons set only what the search leaves showing.
  await openDetail(page);

  // The badge legend is a popover off a one-line hint, not a block in the
  // dialog, so the list keeps its height and shows a screenful of rows.
  const fold = await page.evaluate(sel => {
    const modal = document.querySelector(sel);
    const legend = modal.querySelector('.upstream-rv-legend');
    const list = modal.querySelector('.upstream-modal-list');
    const row = list.querySelector('.upstream-row');
    return {
      hint: !!modal.querySelector('.upstream-rv-hint'),
      badges: !!modal.querySelector('.upstream-row .upstream-rv'),
      legendShown: !!legend && legend.getClientRects().length > 0,
      rowsVisible: row ? Math.floor(list.clientHeight / row.getBoundingClientRect().height) : 0,
    };
  }, MODAL);
  ok(fold.hint === fold.badges, 'the hint is there exactly when a row wears the badge: hint ' + fold.hint + ', badges ' + fold.badges);
  ok(!fold.legendShown, 'the badge legend stays out of the dialog until its tip is hovered');
  ok(fold.rowsVisible >= 8, 'the list shows a screenful of rows at once, shows ' + fold.rowsVisible);
  if (fold.hint) {
    await page.hover(MODAL + ' .upstream-rv-hint .info-tip');
    const shown = await page.evaluate(sel => {
      const legend = document.querySelector(sel + ' .upstream-rv-legend');
      return !!legend && legend.getClientRects().length > 0 && legend.textContent.length > 100;
    }, MODAL);
    ok(shown, 'hovering the tip shows the legend');
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await page.screenshot({ path: require('path').join(process.env.UI_E2E_SHOT_DIR, 'crawler-modes-legend.png') }); } catch (e) {}
    }
    await page.mouse.move(0, 0);
  }
  await page.type(MODAL + ' .upstream-modal-filter', 'MJ12');
  g = await readGroup(page);
  ok(g.visible.length === 1 && g.visible[0] === 'MJ12bot', 'the search must leave MJ12bot alone: ' + JSON.stringify(g.visible));
  await page.click(MODAL + ' .upstream-bulk-btn[data-set="black"]');
  await page.evaluate(sel => {
    const f = document.querySelector(sel + ' .upstream-modal-filter');
    f.value = '';
    f.dispatchEvent(new Event('input'));
  }, MODAL);
  g = await readGroup(page);
  ok(g.visible.length > 100, 'a cleared search must show the whole group again, shows ' + g.visible.length);
  await page.select(MODAL + ' .upstream-row[data-pattern="dotbot"] .upstream-own-sel', 'none');
  g = await readGroup(page);
  ok(g.own['MJ12bot'] === 'black', 'the bulk button must stop MJ12bot');
  ok(g.own['dotbot'] === 'none' && g.own['rogerbot'] === '', 'the bulk button must not reach rows the search hid');
  ok(g.ownCount.indexOf('2') >= 0, 'the group must count two set on their own, shows ' + JSON.stringify(g.ownCount));
  ok(g.actionShown, 'a stopped crawler in the group must show the chain picker');

  // "Only those set on their own" leaves the two.
  await page.click(MODAL + ' .upstream-own-only-chk');
  g = await readGroup(page);
  ok(g.visible.length === 2 && g.visible.includes('MJ12bot') && g.visible.includes('dotbot'),
    'only-own must show just the two: ' + JSON.stringify(g.visible));
  await page.click(MODAL + ' .upstream-modal-save');

  // 2. Escape puts the dialog's rows back.
  await openDetail(page);
  await page.select(MODAL + ' .upstream-row[data-pattern="rogerbot"] .upstream-own-sel', 'white');
  await page.keyboard.press('Escape');
  g = await readGroup(page);
  ok(g.own['rogerbot'] === '', 'Escape must put rogerbot back to following its group');
  ok(g.own['MJ12bot'] === 'black' && g.own['dotbot'] === 'none', 'Escape must keep what an earlier confirm kept');

  // 3. Save: exactly the two are stored, with the group's chain.
  await page.select(GROUP + ' .upstream-action-sel', 'captcha_only');
  await save(page);
  g = await readGroup(page);
  ok(g.own['MJ12bot'] === 'black' && g.own['dotbot'] === 'none', 'the reloaded page must show the two again: ' +
    JSON.stringify({ MJ12bot: g.own['MJ12bot'], dotbot: g.own['dotbot'] }));
  ok(Object.entries(g.own).filter(([, v]) => v !== '').length === 2, 'nothing else may come back set on its own');
  ok(g.ownCount.indexOf('2') >= 0 && g.actionShown && g.action === 'captcha_only',
    'the reloaded group row: count, chain picker and chain: ' + JSON.stringify({ c: g.ownCount, a: g.actionShown, v: g.action }));
  const stored = storedModes();
  if (stored !== null) {
    ok(stored['MJ12bot'] === 'black' && stored['dotbot'] === 'none' && Object.keys(stored).length === 2,
      'config.yml must hold exactly the two: ' + JSON.stringify(stored));
  }

  // 4. Switching the group renames "follow the group (...)" on every row.
  await page.click(GROUP + ' .mode-opt.mode-black');
  g = await readGroup(page);
  ok(g.follow.indexOf(g.labels.black) >= 0, 'after stopping the group, rows must follow "' + g.labels.black + '": ' + g.follow);

  // 5. Back to following the group, the group back to pass: nothing stored.
  await page.click(GROUP + ' .mode-opt.mode-white');
  await openDetail(page);
  await page.click(MODAL + ' .upstream-own-only-chk');
  await page.click(MODAL + ' .upstream-bulk-btn[data-set=""]');
  await page.click(MODAL + ' .upstream-modal-save');
  await page.select(GROUP + ' .upstream-action-sel', 'inherit');
  g = await readGroup(page);
  ok(g.ownCount === '' && !g.actionShown, 'nothing set on its own any more: no count and no chain picker');
  await save(page);
  g = await readGroup(page);
  ok(Object.values(g.own).every(v => v === ''), 'cleanup: every seo crawler must follow its group again');
  const after = storedModes();
  if (after !== null) {
    ok(Object.keys(after).length === 0, 'cleanup: config.yml must hold no crawler set on its own: ' + JSON.stringify(after));
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL crawler-modes:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok crawler-modes');
})().catch(e => { console.error('ERROR crawler-modes: ' + (e.stack || e)); process.exit(1); });
