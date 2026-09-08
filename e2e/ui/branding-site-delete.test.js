// The branding tab's per-site "reset to default" button posts to its own
// formaction on a multipart form.  The CSRF shim used to decorate only the
// form's action with the token, so that button's request carried none and the
// server refused it with "csrf token mismatch" (0.1.25..0.1.40).  This drives
// a real browser through the gesture: create the per-site entry, click the
// button through its confirm dialog, and check the request was accepted and
// the entry is gone.
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
  page.on('dialog', d => d.accept());
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
    // 3) Click it (the confirm dialog is accepted above).  This is the
    //    request that used to come back 403.
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      btn.click(),
    ]);
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
