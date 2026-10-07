// The branding tab's per-site "reset to default" button posts to its own
// formaction on a multipart form.  The CSRF shim used to decorate only the
// form's action with the token, so that button's request carried none and the
// server refused it with "csrf token mismatch" (0.1.25..0.1.40).  This drives
// a real browser through the gesture: create the per-site entry, click the
// button through the admin's confirmation modal, and check the request was
// accepted, the entry is gone, and the banner names the site.
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
  // The delete asks in the admin's own modal; a browser dialog means a
  // confirm() came back.
  page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });
  const posts = [];
  page.on('response', r => {
    const req = r.request();
    if (req.method() === 'POST' && /\/admin\/settings\/(branding\/site\/(save|delete)|save)/.test(r.url())) {
      posts.push({ url: r.url().replace(/_csrf=[^&]*/, '_csrf=…'), status: r.status() });
    }
  });

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // 1) The per-site scope of the branding tab: turn the override on and save,
  //    which creates the site's entry (the multipart form's regular action).
  await page.goto(BASE + '/admin/settings/theme/?scope=' + SITE, { waitUntil: 'networkidle2' });
  const scoped = await page.evaluate(() => {
    const f = document.getElementById('appearance-form');
    if (!f) return { err: 'no appearance form' };
    const cb = f.querySelector('input[name="use_site_override"]');
    if (!cb) return { err: 'no override checkbox (scope not a site?)' };
    if (!cb.checked) cb.click();
    return { action: f.getAttribute('action'), enctype: f.getAttribute('enctype'), checked: cb.checked };
  });
  ok(!scoped.err, 'scoped branding form: ' + (scoped.err || ''));
  ok(scoped.enctype === 'multipart/form-data', 'branding form is multipart, got ' + scoped.enctype);
  ok(/branding\/site\/save\?site=/.test(scoped.action || ''), 'scoped form posts to the site save, got ' + scoped.action);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.evaluate(() => document.getElementById('appearance-form').requestSubmit()),
  ]);
  const saved = posts.find(p => /branding\/site\/save/.test(p.url));
  ok(saved && saved.status !== 403, 'site save must not be a csrf mismatch, got ' + JSON.stringify(saved));

  // 2) Back on the scoped page the entry exists, so the reset button is there.
  await page.goto(BASE + '/admin/settings/theme/?scope=' + SITE, { waitUntil: 'networkidle2' });
  const btn = await page.$('#appearance-form button.scope-delete');
  ok(!!btn, 'per-site entry created: the "reset to default" button is shown');
  if (btn) {
    const fa = await page.evaluate(b => b.getAttribute('formaction'), btn);
    ok(/branding\/site\/delete\?site=/.test(fa || ''), 'reset button posts to its own formaction, got ' + fa);
    // 3) Click it: the modal asks, naming the site; Cancel first must post
    //    nothing.  Then OK -- the request that used to come back 403.
    await btn.click();
    await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 });
    const q = await page.$eval('dialog.ux-dialog[open] h3', e => e.textContent);
    ok(q.includes(SITE), 'the question names the site, got ' + q);
    await page.click('dialog.ux-dialog[open] .ux-dialog-btn:not(.danger):not(.primary)');
    await new Promise(r => setTimeout(r, 400));
    ok(!posts.some(p => /branding\/site\/delete/.test(p.url)), 'Cancel must not post the delete');
    await btn.click();
    await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 });
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.click('dialog.ux-dialog[open] .ux-dialog-btn.danger'),
    ]);
    const banner = await page.$$eval('.banner.ok', els => els.map(e => e.textContent).join(' | '));
    ok(banner.includes(SITE), 'the banner after the delete names the site, got ' + banner);
    const del = posts.find(p => /branding\/site\/delete/.test(p.url));
    ok(!!del, 'the delete POST was sent, posts: ' + JSON.stringify(posts));
    ok(del && del.status !== 403, 'reset to default must not be a csrf mismatch, got ' + JSON.stringify(del));
    ok(del && /_csrf=/.test(del.url), 'the shim must decorate the button formaction with the token, got ' + (del && del.url));
    const body = await page.evaluate(() => document.body.innerText);
    ok(!/csrf token mismatch/i.test(body), 'page must not show the csrf error');
    await page.goto(BASE + '/admin/settings/theme/?scope=' + SITE, { waitUntil: 'networkidle2' });
    const still = await page.$('#appearance-form button.scope-delete');
    ok(!still, 'after the reset the per-site entry is gone (no reset button)');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL branding-site-delete:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok branding-site-delete');
})().catch(e => { console.error('ERROR branding-site-delete: ' + (e.stack || e)); process.exit(1); });
