// Browser-level check of the advisor page and what it shares with bot hunt.
//
// The first cut of the AI-advisor settings tab read its section off the wrong
// struct; the template died mid-render and the page shipped with a heading, an
// intro, and not one input.  The Go wiring test did not notice because the
// <form> tag comes before the failure point.  So the settings check here is
// "every field is in the DOM", not "a form exists".
//
// The advisor page borrows bot hunt's IP popover and BAN dialog through shared
// partials.  Both are exercised on both pages: the popover must fetch, the
// dialog must open from a BAN button and close on cancel without navigating,
// and the reason row must be editable on the advisor page while staying a
// sharing-only field on bot hunt.
//
// run.sh seeds 203.0.113.26 as a two-signal candidate for this.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SEED_IP = '203.0.113.26';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(String(e.message || e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // --- settings > AI advisor: every field, and the page reaches its end -----
  let resp = await page.goto(BASE + '/admin/settings/ai-advisor/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `settings/ai-advisor status ${resp.status()}`);
  const fields = await page.evaluate(() =>
    ['ai_enabled', 'ai_provider', 'ai_model', 'ai_endpoint', 'ai_api_key',
     'ai_notify_enabled', 'ai_notify_interval', 'ai_notify_min_score']
      .filter(n => !document.querySelector(`[name="${n}"]`)));
  ok(fields.length === 0, `settings/ai-advisor is missing fields: ${fields.join(', ')}`);
  const keyVal = await page.evaluate(() => (document.querySelector('[name="ai_api_key"]') || {}).value);
  ok(keyVal === '', `the API key field must render empty, got ${JSON.stringify(keyVal)}`);

  // --- advisor page ----------------------------------------------------------
  resp = await page.goto(BASE + '/admin/advisor/?window=24', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/advisor/ status ${resp.status()}`);
  const adv = await page.evaluate((ip) => {
    const row = Array.from(document.querySelectorAll('table.cands tbody tr'))
      .find(r => (r.querySelector('.ipclick') || {}).dataset && r.querySelector('.ipclick').dataset.ip === ip);
    if (!row) return { missing: true, rows: document.querySelectorAll('table.cands tbody tr').length };
    const sigs = Array.from(row.querySelectorAll('.sig')).map(s => s.textContent.trim());
    const log = row.querySelector('a.loglink');
    return {
      sigs,
      hasFlag: !!row.querySelector('.ipclick img.flag'),
      hasUA: !!row.querySelector('td.ua .uaclick'),
      loglink: log ? log.getAttribute('href') : null,
      hasBanForm: !!row.querySelector('form.js-ban-form button'),
      dialog: !!document.getElementById('ban-dialog'),
      ipPop: !!document.getElementById('ip-popover'),
      uaPop: !!document.getElementById('ua-popover'),
      navAdvisor: !!document.querySelector('header .nav a[href$="/admin/advisor/"]'),
    };
  }, SEED_IP);
  if (adv.missing) {
    ok(false, `no candidate row for ${SEED_IP} (${adv.rows} rows) -- run.sh seeding changed or the engine regressed`);
  } else {
    ok(adv.sigs.includes('challenge_hammering') && adv.sigs.includes('scanner_paths'),
      `expected both signals on the seed row, got ${JSON.stringify(adv.sigs)}`);
    ok(adv.hasFlag, 'the IP cell has no country flag');
    ok(adv.hasUA, 'the UA cell has no popover trigger');
    ok(adv.loglink && adv.loglink.indexOf('/admin/hunt/?ip=' + SEED_IP) >= 0,
      `the magnifier does not open the raw events for the target: ${adv.loglink}`);
    ok(adv.hasBanForm, 'the row has no BAN button');
    ok(adv.dialog && adv.ipPop && adv.uaPop, 'a shared popover / dialog element is missing on the advisor page');
    ok(adv.navAdvisor, 'the global nav has no advisor entry');

    // IP popover: hover fetches the lookup and shows the address.
    const popText = await page.evaluate(async (ip) => {
      const el = document.querySelector(`.ipclick[data-ip="${ip}"]`);
      el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: 300, clientY: 300 }));
      await new Promise(r => setTimeout(r, 900));
      return document.getElementById('ip-popover').textContent;
    }, SEED_IP);
    ok(popText.indexOf(SEED_IP) >= 0, `the IP popover did not show the address: ${JSON.stringify(popText.slice(0, 80))}`);

    // UA popover: the clipped cell opens the full string.
    const uaText = await page.evaluate(async () => {
      document.querySelector('td.ua .uaclick').dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
      await new Promise(r => setTimeout(r, 500));
      return document.getElementById('ua-popover').textContent;
    });
    ok(uaText.indexOf('UI-E2E-hammer') >= 0, `the UA popover did not show the full user agent: ${JSON.stringify(uaText.slice(0, 80))}`);

    // BAN dialog: opens from the row, reason editable and prefilled, cancel
    // closes it without leaving the page.
    const before = page.url();
    await page.click(`table.cands tbody tr form.js-ban-form button`);
    await new Promise(r => setTimeout(r, 300));
    const dlg = await page.evaluate(() => {
      const d = document.getElementById('ban-dialog');
      const row = document.getElementById('ban-dialog-reason-row');
      const reason = document.getElementById('ban-dialog-reason');
      return {
        open: d.open,
        target: document.getElementById('ban-dialog-target').textContent,
        reasonShown: row && getComputedStyle(row).display !== 'none',
        reasonValue: reason ? reason.value : null,
      };
    });
    ok(dlg.open, 'the BAN dialog did not open from the advisor row');
    ok(dlg.target.indexOf(SEED_IP) >= 0, `the dialog names the wrong target: ${dlg.target}`);
    ok(dlg.reasonShown, 'the reason row is hidden on the advisor page');
    ok(dlg.reasonValue && dlg.reasonValue.indexOf('advisor:') === 0,
      `the reason is not prefilled from the signals: ${JSON.stringify(dlg.reasonValue)}`);
    await page.click('#ban-dialog button[value="cancel"]');
    await new Promise(r => setTimeout(r, 300));
    const afterCancel = await page.evaluate(() => document.getElementById('ban-dialog').open);
    ok(!afterCancel, 'cancel did not close the dialog');
    ok(page.url() === before, `cancel navigated away: ${page.url()}`);
  }

  // --- bot hunt: the same dialog still behaves as before -------------------
  resp = await page.goto(BASE + '/admin/hunt/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);
  const hunt = await page.evaluate(() => ({
    dialog: !!document.getElementById('ban-dialog'),
    ipPop: !!document.getElementById('ip-popover'),
    banBtn: !!document.querySelector('.rank-card-ip form.js-ban-form button'),
  }));
  ok(hunt.dialog && hunt.ipPop, 'bot hunt lost its dialog / IP popover after the partial extraction');
  if (hunt.banBtn) {
    await page.click('.rank-card-ip form.js-ban-form button');
    await new Promise(r => setTimeout(r, 300));
    const hd = await page.evaluate(() => ({
      open: document.getElementById('ban-dialog').open,
      reasonShown: getComputedStyle(document.getElementById('ban-dialog-reason-row')).display !== 'none',
    }));
    ok(hd.open, 'the bot-hunt BAN dialog did not open');
    ok(!hd.reasonShown, 'on bot hunt the reason row must stay hidden until sharing is ticked');
    await page.click('#ban-dialog button[value="cancel"]');
  } else {
    ok(false, 'the IP ranking has no BAN button to test the dialog with');
  }

  ok(jsErrors.length === 0, `page JS errors: ${jsErrors.join(' | ')}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('advisor: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
