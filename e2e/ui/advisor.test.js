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
const sleep = ms => new Promise(r => setTimeout(r, ms));

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
  // Model picker: presets in a select, custom reveals the free-text field.
  const picker = await page.evaluate(() => {
    const sel = document.getElementById('ai_model_sel'), txt = document.getElementById('ai_model');
    if (!sel || !txt) return { missing: true };
    const hiddenBefore = getComputedStyle(txt).display === 'none';
    sel.value = '__custom__'; sel.dispatchEvent(new Event('change', { bubbles: true }));
    const shownAfter = getComputedStyle(txt).display !== 'none';
    return { options: sel.options.length, hiddenBefore, shownAfter };
  });
  ok(!picker.missing, 'the model picker is missing');
  ok(!picker.missing && picker.options >= 4, `the picker has too few options: ${JSON.stringify(picker)}`);
  ok(!picker.missing && picker.hiddenBefore && picker.shownAfter, `custom did not reveal the text field: ${JSON.stringify(picker)}`);
  // The list follows the provider: openai's models under openai, and the
  // default becomes openai's.
  const follow = await page.evaluate(() => {
    const prov = document.querySelector('[name="ai_provider"]'), sel = document.getElementById('ai_model_sel'), txt = document.getElementById('ai_model');
    if (!prov || !sel || !txt) return { missing: true };
    txt.value = 'claude-opus-5';
    prov.value = 'openai'; prov.dispatchEvent(new Event('change', { bubbles: true }));
    const ids = Array.from(sel.options).map(o => o.value);
    return { ids, placeholder: txt.placeholder, value: txt.value, hidden: getComputedStyle(txt).display === 'none' };
  });
  ok(!follow.missing && follow.ids.some(v => v.startsWith('gpt')) && !follow.ids.some(v => v.startsWith('claude')),
    `under openai the picker must list openai models only: ${JSON.stringify(follow.ids)}`);
  ok(!follow.missing && follow.placeholder === 'gpt-4o-mini' && follow.value === '' && follow.hidden,
    `switching provider must fall back to its default: ${JSON.stringify(follow)}`);

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
      navAdvisor: !document.querySelector('header .nav a[href$="/admin/advisor/"]') &&
        !!document.querySelector('.ban-tabs a.active[href$="/admin/advisor/"]'),
      // The harness has no key: the page must not offer (or run) the model.
      aiButton: !!document.querySelector('form[action$="/admin/advisor/ai-run"]'),
      // The heading and the traffic column each carry a ? help popover.
      helpH1: !!document.querySelector('main h1 .info-tip .info-popup'),
      helpTraffic: !!document.querySelector('table.cands thead th .info-tip .info-popup'),
      // The traffic cell: served -> passed on the main line, the middle
      // stages under it, the window as a compact range.
      traffic: (row.querySelector('.tf-main') || {}).textContent || '',
      trafficSub: (row.querySelector('.tf-sub') || {}).textContent || '',
      trafficWhen: !!row.querySelector('.tf-when time.js-datetime-short[data-ts]'),
      // Sample paths: the long one is clipped (popover), the short ones are not.
      clippedPaths: Array.from(row.querySelectorAll('td .clamp-v.uaclick')).filter(e => e.classList.contains('clipped')).length,
      plainPaths: Array.from(row.querySelectorAll('td .clamp-v.uaclick')).filter(e => !e.classList.contains('clipped')).length,
      // The rows carry the slot the model's answer is filled into in place.
      hasSlot: !!row.querySelector('.ai-slot[data-ai="1"]') && !!document.getElementById('cands-body'),
      // ... and it takes no room while it has nothing to say.
      slotHidden: getComputedStyle(row.querySelector('.ai-slot[data-ai="1"]')).display === 'none',
      // The shared partials expose their wiring for swapped-in rows.
      rewire: Array.isArray(window.unmaskRewire) && window.unmaskRewire.length >= 2,
      // The attention filter.
      filter: !!document.querySelector('select[name="min"] option[value="all"]'),
      // Six columns: the origin (ASN / rDNS) lives under the address now.
      ths: document.querySelectorAll('table.cands thead th').length,
      // The engine's score on the row (hammering 3 + scanner 3 for the seed).
      score: (row.querySelector('.score') || {}).textContent || '',
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
    ok(adv.navAdvisor, 'advisor must live in the BAN tab strip, not the global nav');
    ok(!adv.aiButton, 'with no key saved the page must not offer the model button');
    ok(adv.helpH1 && adv.helpTraffic, 'the ? help popovers are missing on the heading / traffic column');
    ok(adv.hasSlot, 'the seed row has no eligible .ai-slot / the table body has no id for the in-place swap');
    ok(adv.slotHidden, 'the empty AI sub-row must be hidden');
    ok(adv.rewire, 'the IP popover / BAN dialog partials did not register their re-wire hooks');
    ok(adv.filter, 'the attention filter select is missing');
    ok(adv.ths === 6, `expected 6 columns (origin folded under the address), got ${adv.ths}`);
    ok(/\b6\b/.test(adv.score), `the seed row must show its score 6: ${JSON.stringify(adv.score)}`);
    const main = (adv.traffic.match(/\d+/g) || []).map(Number);
    ok(main.length === 2 && main[0] === 35 && main[1] === 0,
      `the traffic main line must read 35 served -> 0 passed: ${JSON.stringify(adv.traffic.trim().slice(0, 80))}`);
    ok((adv.trafficSub.match(/\d+/g) || []).length === 3, `the middle stages line must carry three counts: ${JSON.stringify(adv.trafficSub.trim())}`);
    ok(adv.trafficWhen, 'the window must be a tz-aware compact time range');
    ok(adv.clippedPaths >= 1 && adv.plainPaths >= 1,
      `expected both a clipped and an unclipped sample path, got clipped=${adv.clippedPaths} plain=${adv.plainPaths}`);

    // IP popover: hover fetches the lookup and shows the address.
    const popText = await page.evaluate(async (ip) => {
      const el = document.querySelector(`.ipclick[data-ip="${ip}"]`);
      el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: 300, clientY: 300 }));
      await new Promise(r => setTimeout(r, 900));
      return document.getElementById('ip-popover').textContent;
    }, SEED_IP);
    ok(popText.indexOf(SEED_IP) >= 0, `the IP popover did not show the address: ${JSON.stringify(popText.slice(0, 80))}`);

    // Sample paths: hovering a value that fits opens nothing; hovering the
    // clipped one opens the full path.
    const pathPop = await page.evaluate(async () => {
      const pop = document.getElementById('ua-popover');
      const visible = () => !!(pop.offsetWidth || pop.offsetHeight);
      const plain = Array.from(document.querySelectorAll('table.cands td .clamp-v.uaclick')).find(e => !e.classList.contains('clipped'));
      const clip = Array.from(document.querySelectorAll('table.cands td .clamp-v.uaclick')).find(e => e.classList.contains('clipped'));
      if (!plain || !clip) return { missing: true };
      plain.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: 300, clientY: 400 }));
      await new Promise(r => setTimeout(r, 500));
      const plainShown = visible() && pop.textContent.indexOf(plain.dataset.ua) >= 0;
      plain.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
      clip.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, clientX: 300, clientY: 400 }));
      await new Promise(r => setTimeout(r, 500));
      const clipShown = visible() && pop.textContent.indexOf('ui-e2e-long-path-to-clip') >= 0;
      clip.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
      return { plainShown, clipShown, plainCursor: getComputedStyle(plain).cursor };
    });
    ok(!pathPop.missing, 'no clipped / unclipped sample path pair to test the popover rule with');
    ok(!pathPop.missing && !pathPop.plainShown, 'a sample path that fits must not open a popover');
    ok(!pathPop.missing && pathPop.clipShown, 'the clipped sample path must open the full value');
    ok(!pathPop.missing && pathPop.plainCursor !== 'help', `an unclipped value must not advertise a popover (cursor ${pathPop.plainCursor})`);

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

  // --- dismiss -> gone; show dismissed -> back, marked; un-dismiss -> plain --
  const findRow = (ip) => Array.from(document.querySelectorAll('#cands-body tr'))
    .find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
  await page.goto(BASE + '/admin/advisor/?window=24', { waitUntil: 'networkidle2' });
  const hasDismiss = await page.evaluate((ip) => {
    const r = Array.from(document.querySelectorAll('#cands-body tr')).find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
    return !!(r && r.querySelector('form[action$="/admin/advisor/dismiss"] button'));
  }, SEED_IP);
  if (!hasDismiss) {
    ok(false, 'the seed row has no dismiss button');
  } else {
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.evaluate((ip) => {
        const r = Array.from(document.querySelectorAll('#cands-body tr')).find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
        r.querySelector('form[action$="/admin/advisor/dismiss"] button').click();
      }, SEED_IP),
    ]);
    const gone = await page.evaluate((ip) => !Array.from(document.querySelectorAll('#cands-body .ipclick')).some(e => e.dataset.ip === ip), SEED_IP);
    ok(gone, 'a dismissed candidate must leave the list');
    await page.goto(BASE + '/admin/advisor/?window=24&show_dismissed=1', { waitUntil: 'networkidle2' });
    const back = await page.evaluate((ip) => {
      const r = Array.from(document.querySelectorAll('#cands-body tr')).find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
      return {
        present: !!r,
        marked: !!(r && r.classList.contains('dismissed') && r.querySelector('.state.dismissed')),
        undismiss: !!(r && r.querySelector('form[action$="/admin/advisor/undismiss"] button')),
        checked: !!(document.querySelector('input[name="show_dismissed"]') || {}).checked,
      };
    }, SEED_IP);
    ok(back.present && back.marked && back.undismiss && back.checked, `show dismissed must bring the row back, marked, with un-dismiss: ${JSON.stringify(back)}`);
    if (back.undismiss) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2' }),
        page.evaluate((ip) => {
          const r = Array.from(document.querySelectorAll('#cands-body tr')).find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
          r.querySelector('form[action$="/admin/advisor/undismiss"] button').click();
        }, SEED_IP),
      ]);
      await page.goto(BASE + '/admin/advisor/?window=24', { waitUntil: 'networkidle2' });
      const plain = await page.evaluate((ip) => {
        const r = Array.from(document.querySelectorAll('#cands-body tr')).find(r => r.querySelector('.ipclick') && r.querySelector('.ipclick').dataset.ip === ip);
        return !!r && !r.classList.contains('dismissed');
      }, SEED_IP);
      ok(plain, 'after un-dismissing the candidate is back in the default list, unmarked');
    }
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
  // A fingerprint target: the dialog measures the collateral before it lets
  // the operator confirm.  The seed fingerprint never passed -> allowed.
  const ja4Btn = await page.evaluate(() => !!document.querySelector('.rank-card-ja4 form.js-ban-form button'));
  if (ja4Btn) {
    await page.click('.rank-card-ja4 form.js-ban-form button');
    await sleep(900);
    const cd = await page.evaluate(() => {
      const col = document.getElementById('ban-dialog-collateral');
      return {
        open: document.getElementById('ban-dialog').open,
        shown: !!col && getComputedStyle(col).display !== 'none',
        level: col ? col.className.replace('ban-dialog-collateral', '').trim() : '',
        text: (document.getElementById('ban-dialog-collateral-body') || {}).textContent || '',
        okEnabled: !(document.getElementById('ban-dialog-ok') || { disabled: true }).disabled,
      };
    });
    ok(cd.open && cd.shown, 'a fingerprint ban must show the collateral check');
    ok(cd.level === 'none' && cd.okEnabled, `the seed fingerprint has no passer: level none, ban allowed -- got ${JSON.stringify(cd)}`);
    await page.click('#ban-dialog button[value="cancel"]');
    await sleep(200);
    // ... and an address target shows no check and stays enabled.
    await page.click('.rank-card-ip form.js-ban-form button');
    await sleep(300);
    const ipd = await page.evaluate(() => ({
      shown: getComputedStyle(document.getElementById('ban-dialog-collateral')).display !== 'none',
      okEnabled: !document.getElementById('ban-dialog-ok').disabled,
    }));
    ok(!ipd.shown && ipd.okEnabled, `an address target has no collateral check: ${JSON.stringify(ipd)}`);
    await page.click('#ban-dialog button[value="cancel"]');
    await sleep(200);
  } else {
    ok(false, 'the JA4 ranking has no BAN button to test the collateral check with');
  }
  if (hunt.banBtn) {
    await page.click('.rank-card-ip form.js-ban-form button');
    await new Promise(r => setTimeout(r, 300));
    const hd = await page.evaluate(() => {
      const more = document.getElementById('ban-dialog-share-more');
      const shownBefore = getComputedStyle(more).display !== 'none';
      const cb = document.getElementById('ban-dialog-share');
      cb.checked = true; cb.dispatchEvent(new Event('change', { bubbles: true }));
      const shownAfter = getComputedStyle(more).display !== 'none';
      cb.checked = false; cb.dispatchEvent(new Event('change', { bubbles: true }));
      return {
        open: document.getElementById('ban-dialog').open,
        kind: document.getElementById('ban-dialog-kind').textContent.trim(),
        reasonShown: getComputedStyle(document.getElementById('ban-dialog-reason-row')).display !== 'none',
        shareFolded: !shownBefore, shareUnfolds: shownAfter,
        afterNote: !!document.querySelector('#ban-dialog .ban-dialog-after a[href$="/admin/bans/"]'),
        effect: ((document.querySelector('#ban-dialog .ban-dialog-effect') || {}).textContent || '').trim(),
        defaultOK: (document.querySelector('#ban-dialog form button[type="submit"]') || {}).value === 'ok',
      };
    });
    ok(hd.open, 'the bot-hunt BAN dialog did not open');
    ok(hd.reasonShown, 'the reason belongs to the BAN and shows on bot hunt too');
    ok(hd.kind.length > 0, 'the dialog must name the target kind (IP / JA4)');
    ok(hd.shareFolded && hd.shareUnfolds, `sharing must be one folded line that unfolds when ticked: ${JSON.stringify(hd)}`);
    ok(hd.afterNote, 'the dialog must say where the ban can be reviewed or lifted');
    ok(hd.effect.length > 0, 'the dialog must say what the ban does (challenge vs refusal)');
    ok(hd.defaultOK, 'Enter must confirm, not cancel (the default submit button is OK)');
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
