// A site's form on the challenge and theme tabs shows what the site gets --
// its own values over Default's -- and saving it as shown changes nothing.
//
// The form used to show the site's record itself, where a field the site had
// not set read as the built-in value: under a one-day Default the site's PoW
// cookie field said seven days, and one save of the form fixed seven days for
// the site.  The theme's "customize" boxes were a second way to lose what the
// page showed: they carried no value, so the browser posted "on", the server
// took only "1", and no colour was ever saved from the page -- for a site or
// for Default.  Both are things only a browser does (the fields a page's
// script disables, what an input without a value posts), hence this test
// beside the handler ones.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SITE = 'ui-e2e.example';   // the one site run.sh declares

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const open = (tab, site) => page.goto(BASE + '/admin/settings/' + tab + '/' + (site ? '?scope=' + site : ''), { waitUntil: 'networkidle2' });
  // The tab's one scope-aware form, saved the way its Save button saves it.
  const save = async () => {
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.evaluate(() => document.querySelector('form.scope-aware-form').requestSubmit()),
    ]);
    const err = await page.$$eval('.banner.err, .banner.error', els => els.map(e => e.textContent.trim()).join(' | '));
    ok(!err, 'the save was refused: ' + err);
  };
  const setField = (name, value) => page.evaluate((name, value) => {
    const el = document.querySelector('form.scope-aware-form [name="' + name + '"]');
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }, name, value);
  const setBox = (name, on) => page.evaluate((name, on) => {
    const cb = document.querySelector('form.scope-aware-form input[type="checkbox"][name="' + name + '"]');
    if (cb.checked !== on) cb.click();
    return cb.checked;
  }, name, on);
  // What the form shows for a field, and whether the field is marked inherited.
  const field = name => page.evaluate(name => {
    const el = document.querySelector('form.scope-aware-form [name="' + name + '"]');
    if (!el) return null;
    const f = el.closest('.field');
    return { value: el.value, checked: !!el.checked, disabled: !!el.disabled, inherited: !!(f && f.querySelector('.inherit-chip')) };
  }, name);
  // The site's record on this tab dropped, through the admin's own modal.
  const dropSite = async (tab) => {
    await open(tab, SITE);
    const btn = await page.$('form.scope-aware-form button.scope-delete');
    if (!btn) return;
    await btn.click();
    await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 });
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.click('dialog.ux-dialog[open] .ux-dialog-btn.danger'),
    ]);
  };

  // ---- the challenge tab ---------------------------------------------------
  // Default: a one-day PoW cookie.
  await open('challenge');
  await setField('pow_cookie_valid_seconds', '86400');
  await save();

  // The site: the override on, its own difficulty, nothing else touched.
  await open('challenge', SITE);
  let f = await field('pow_cookie_valid_seconds');
  ok(f && f.value === '86400', 'a site with no record is shown Default\'s PoW cookie (86400), got ' + JSON.stringify(f));
  await setBox('use_site_override', true);
  await setField('pow_difficulty', '20');
  await save();

  // The page the save lands on: the site's own number is its own, and the
  // cookie is Default's one day, marked as inherited -- not seven days.
  await open('challenge', SITE);
  f = await field('pow_cookie_valid_seconds');
  ok(f && f.value === '86400', 'the site\'s form shows the PoW cookie the site gets (86400, Default\'s), got ' + JSON.stringify(f));
  ok(f && f.inherited, 'the PoW cookie, which the site does not set, is marked inherited');
  f = await field('pow_difficulty');
  ok(f && f.value === '20' && !f.inherited, 'the difficulty the site set is shown as its own, got ' + JSON.stringify(f));

  // Saved as shown, and then Default moves: the site follows.
  await save();
  await open('challenge');
  await setField('pow_cookie_valid_seconds', '43200');
  await save();
  await open('challenge', SITE);
  f = await field('pow_cookie_valid_seconds');
  ok(f && f.value === '43200', 'after a save of the form as shown the site still follows Default\'s PoW cookie (43200), got ' + JSON.stringify(f));
  f = await field('pow_difficulty');
  ok(f && f.value === '20', 'and keeps its own difficulty (20), got ' + JSON.stringify(f));

  // The override off: every control but the toggle is disabled, and what
  // they show is still the site's record (20), for the day it is on again.
  await setBox('use_site_override', false);
  f = await field('pow_difficulty');
  ok(f && f.disabled && f.value === '20', 'with the override unticked the difficulty is disabled and still shows the site\'s 20, got ' + JSON.stringify(f));
  await save();
  await open('challenge', SITE);
  f = await field('pow_difficulty');
  ok(f && f.disabled && f.value === '20', 'a record that is off shows its own difficulty (20), disabled, got ' + JSON.stringify(f));
  f = await field('use_site_override');
  ok(f && !f.checked, 'the toggle of a record that is off is unticked');

  await dropSite('challenge');
  await open('challenge');
  await setField('pow_cookie_valid_seconds', '604800');
  await save();

  // ---- the theme tab: a theme's own colours --------------------------------
  // Default: the dark theme recoloured (with the colours the form offers).
  await open('theme');
  await setBox('custom_on_dark', true);
  await save();
  await open('theme');
  f = await field('custom_on_dark');
  ok(f && f.checked, 'Default: the dark theme\'s "customize" box, ticked and saved, is ticked on the page the save lands on');

  // The site is shown Default's colours; it adds its own for the paper theme.
  await open('theme', SITE);
  f = await field('custom_on_dark');
  ok(f && f.checked, 'a site with no record is shown Default\'s colours (dark ticked)');
  await setBox('use_site_override', true);
  await setBox('custom_on_paper', true);
  await save();
  await open('theme', SITE);
  f = await field('custom_on_paper');
  ok(f && f.checked, 'the site: the paper theme\'s colours, ticked and saved, are ticked on the page the save lands on');
  f = await field('custom_on_dark');
  ok(f && f.checked, 'the site: the dark theme\'s colours, which the form showed and the save left alone, are still ticked');

  // No colours of its own for the site, under a Default that has some.
  await setBox('custom_on_paper', false);
  await setBox('custom_on_dark', false);
  await save();
  await open('theme', SITE);
  f = await field('custom_on_dark');
  ok(f && !f.checked, 'the site: every "customize" box unticked and saved comes back unticked (dark)');
  f = await field('custom_on_paper');
  ok(f && !f.checked, 'the site: every "customize" box unticked and saved comes back unticked (paper)');
  await open('theme');
  f = await field('custom_on_dark');
  ok(f && f.checked, 'Default keeps its own colours when a site turns its colours off');

  await dropSite('theme');
  await open('theme');
  await setBox('custom_on_dark', false);
  await save();
  await open('theme');
  f = await field('custom_on_dark');
  ok(f && !f.checked, 'Default: the box unticked and saved is unticked');

  await browser.close();
  if (fails.length) {
    console.error('FAIL site-form-inherit:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok site-form-inherit');
})().catch(e => { console.error('ERROR site-form-inherit: ' + (e.stack || e)); process.exit(1); });
