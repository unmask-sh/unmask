// A theme's own colours, set on the design page, are saved.
//
// Each theme card has a "customize" box and two colours; the deny and ban
// pages have the same per light / dark.  The boxes carried no value, so the
// browser posted "on" for a ticked one; the server reads "1" and took every
// box for unticked.  The save was reported as taken, and the page it landed
// on showed the box unticked and the theme in its built-in colours: no colour
// could be set from the page at all.  Only a browser posts "on" for such a
// box -- the handler's tests wrote the "1" themselves -- hence this test.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

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

  const open = () => page.goto(BASE + '/admin/settings/theme/', { waitUntil: 'networkidle2' });
  const save = async () => {
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.evaluate(() => document.getElementById('appearance-form').requestSubmit()),
    ]);
    const err = await page.$$eval('.banner.err, .banner.error', els => els.map(e => e.textContent.trim()).join(' | '));
    ok(!err, 'the save was refused: ' + err);
  };
  const setBox = (name, on) => page.evaluate((name, on) => {
    const cb = document.querySelector('#appearance-form input[type="checkbox"][name="' + name + '"]');
    if (cb.checked !== on) cb.click();
  }, name, on);
  const setColor = (name, value) => page.evaluate((name, value) => {
    document.querySelector('#appearance-form input[name="' + name + '"]').value = value;
  }, name, value);
  const read = names => page.evaluate(names => {
    const o = {};
    names.forEach(n => {
      const el = document.querySelector('#appearance-form input[name="' + n + '"]');
      o[n] = el ? (el.type === 'checkbox' ? el.checked : el.value) : null;
    });
    return o;
  }, names);

  const boxes = ['custom_on_dark', 'deny_custom_on_light', 'ban_custom_on_dark'];
  const colors = ['custom_bg_dark', 'custom_text_dark'];

  // Tick a box of each kind, give the dark theme two colours, save.
  await open();
  for (const b of boxes) await setBox(b, true);
  await setColor('custom_bg_dark', '#102030');
  await setColor('custom_text_dark', '#f0e0d0');
  await save();
  await open();
  let got = await read(boxes.concat(colors));
  for (const b of boxes) ok(got[b] === true, `"${b}", ticked and saved, is ticked on the page the save lands on (got ${got[b]})`);
  ok(got.custom_bg_dark === '#102030' && got.custom_text_dark === '#f0e0d0',
    'the dark theme\'s colours are the ones that were saved, got ' + got.custom_bg_dark + ' / ' + got.custom_text_dark);

  // And the page drawn with them: the dark theme's preview, loaded as the
  // theme cards load it, has the saved background.
  const preview = await browser.newPage();
  await preview.goto(BASE + '/challenge/?_test_ja4=0&theme=dark&_preview=1', { waitUntil: 'networkidle2' });
  const drawn = await preview.evaluate(() => ({
    html: getComputedStyle(document.documentElement).backgroundColor,
    body: getComputedStyle(document.body).backgroundColor,
    source: document.documentElement.outerHTML.indexOf('#102030') >= 0,
  }));
  await preview.close();
  ok(drawn.html === 'rgb(16, 32, 48)' || drawn.body === 'rgb(16, 32, 48)',
    'the challenge page in the dark theme is drawn with the saved background (#102030), got ' + JSON.stringify(drawn));

  // Unticked again and saved: back to the built-in colours.
  for (const b of boxes) await setBox(b, false);
  await save();
  await open();
  got = await read(boxes);
  for (const b of boxes) ok(got[b] === false, `"${b}", unticked and saved, is unticked (got ${got[b]})`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL theme-colors-save:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok theme-colors-save');
})().catch(e => { console.error('ERROR theme-colors-save: ' + (e.stack || e)); process.exit(1); });
