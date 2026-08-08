// Browser-level check that the settings tab lives in the PATH now
// (/admin/settings/{tab}/) rather than ?tab=X.  Verifies, against a real
// running admin (real ServeMux, real templates), that:
//   - the bare index and a path-tab both render (200, not 404),
//   - the rendered nav links are path-form and carry no ?tab= anywhere,
//   - clicking a nav item lands on the path URL,
//   - a cross-tab hint that uses a relative ../network/ link resolves to the
//     sibling tab (the one fragile spot of the path move),
//   - the asn/suggest literal sub-route is not shadowed by {tab}.
//
// Driven by run.sh (throwaway admin). Env: UI_E2E_BASE, UI_E2E_USER,
// UI_E2E_PASS, CHROME_BIN, UI_E2E_OUT.
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

  // ---- login (same flow comp-card uses) ----
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // ---- bare index renders (= overview/top) ----
  let resp = await page.goto(BASE + '/admin/settings/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `bare /admin/settings/ status ${resp.status()}`);

  // ---- a path tab renders, is the active tab, and nav is path-form ----
  resp = await page.goto(BASE + '/admin/settings/sites/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/sites/ status ${resp.status()}`);
  const sites = await page.evaluate(() => {
    // Scope to the settings tab rail; the global header nav also marks its
    // "Settings" entry active (it points at the bare index).
    const active = document.querySelector('.settings-nav a.active');
    return {
      body: document.documentElement.outerHTML,
      activeHref: active ? active.getAttribute('href') : '',
      hasSitesForm: !!document.querySelector('form[action*="save?section=sites"]'),
    };
  });
  ok(sites.hasSitesForm, 'sites tab did not render its save form (wrong tab served for the path)');
  ok(sites.activeHref.endsWith('/admin/settings/sites/'),
     `active nav href ${JSON.stringify(sites.activeHref)} is not the path form`);
  ok(!sites.body.includes('?tab='), 'rendered settings page still contains a ?tab= link');
  ok(sites.body.includes('/admin/settings/network/'),
     'nav is missing the path-form link to the network tab');

  // ---- clicking a nav item lands on the path URL ----
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('a[href$="/admin/settings/network/"]'),
  ]);
  ok(page.url().endsWith('/admin/settings/network/'),
     `nav click landed on ${page.url()}, want .../admin/settings/network/`);

  // ---- a relative ../network/ cross-link resolves to the sibling tab ----
  resp = await page.goto(BASE + '/admin/settings/geo/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/geo/ status ${resp.status()}`);
  const rel = await page.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a'))
      .find(x => x.getAttribute('href') === '../network/');
    return a ? a.href : null; // .href is the browser-resolved absolute URL
  });
  ok(rel !== null, 'geo tab is missing the relative ../network/ cross-link (mmdb hint)');
  if (rel !== null) {
    ok(rel.endsWith('/admin/settings/network/'),
       `../network/ resolved to ${rel}, want .../admin/settings/network/`);
  }

  // ---- the asn/suggest literal sub-route is not shadowed by {tab} ----
  resp = await page.goto(BASE + '/admin/settings/asn/suggest?q=goog', { waitUntil: 'networkidle2' });
  ok(resp.status() !== 404, `asn/suggest returned 404 -- shadowed by {tab}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('settings-routing: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
