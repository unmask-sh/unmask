// Browser-level check of the pass-cookie reuse cap's card on the rate-limit tab.
// Against a real running admin (real templates + the save handler), verifies:
//   - the card ships on, with the seeds (500 requests every 60 minutes for one
//     pass, 10,000 a day / 2,000 at once for an address) as placeholders and
//     captcha_only preselected,
//   - enabling it with values, a window of its own for one pass and deny
//     survives a save (and the save lands back on the rate-limit tab, with the
//     reload banner: the zone renders),
//   - a per-pass figure below its window's minutes is stopped on the field,
//     before the save: the field turns red, the note under the card says why
//     with both figures (a blank field counting at its placeholder), and
//     nothing is posted,
//   - switching it off sticks, and the default comes back (the test leaves the
//     config as found).
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

async function card(page) {
  return page.evaluate(() => {
    const q = (n) => document.querySelector('[name="' + n + '"]');
    return {
      present: !!document.getElementById('rl-reuse'),
      enabled: q('reuse_enabled') ? q('reuse_enabled').checked : null,
      passRequests: q('reuse_pass_requests') ? q('reuse_pass_requests').value : null,
      passRequestsPh: q('reuse_pass_requests') ? q('reuse_pass_requests').placeholder : null,
      passMinutes: q('reuse_pass_minutes') ? q('reuse_pass_minutes').value : null,
      passMinutesPh: q('reuse_pass_minutes') ? q('reuse_pass_minutes').placeholder : null,
      oldHourField: !!q('reuse_pass_per_hour'),
      perDay: q('reuse_per_day') ? q('reuse_per_day').value : null,
      perDayPh: q('reuse_per_day') ? q('reuse_per_day').placeholder : null,
      burst: q('reuse_burst') ? q('reuse_burst').value : null,
      burstPh: q('reuse_burst') ? q('reuse_burst').placeholder : null,
      action: q('reuse_action') ? q('reuse_action').value : null,
      banner: (document.querySelector('.banner.ok') || {}).textContent || '',
      path: location.pathname,
    };
  });
}

async function save(page) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('form[action*="section=rate_limit"] button[type="submit"]'),
  ]);
}

async function fill(page, v) {
  await page.evaluate((v) => {
    const q = (n) => document.querySelector('[name="' + n + '"]');
    q('reuse_enabled').checked = v.enabled;
    // Typed, as an operator does: the card's own check listens for input.
    const type = (n, val) => {
      const el = q(n);
      el.value = val;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    };
    type('reuse_pass_requests', v.passRequests);
    type('reuse_pass_minutes', v.passMinutes);
    q('reuse_per_day').value = v.perDay;
    q('reuse_burst').value = v.burst;
    q('reuse_action').value = v.action;
  }, v);
}

// The per-pass pair's own check: is the figure field valid, is it drawn red,
// and what the note under the card says.
async function passCheck(page) {
  return page.evaluate(() => {
    const n = document.querySelector('[name="reuse_pass_requests"]');
    const note = document.getElementById('rl-reuse-pass-err');
    const border = getComputedStyle(n).borderTopColor;
    return {
      valid: n.checkValidity(),
      red: border === 'rgb(220, 38, 38)',
      border,
      noteHidden: !note || note.hidden || getComputedStyle(note).display === 'none',
      note: note ? note.textContent : '',
    };
  });
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/settings/rate-limit/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/settings/rate-limit/ status ${resp.status()}`);
  const first = await card(page);
  ok(first.present, 'the reuse cap card is missing');
  ok(first.enabled === true, 'the cap must ship on');
  ok(first.passRequests === '' && first.passRequestsPh === '500', `per pass, requests: value "${first.passRequests}", placeholder "${first.passRequestsPh}"`);
  ok(first.passMinutes === '' && first.passMinutesPh === '60', `per pass, minutes: value "${first.passMinutes}", placeholder "${first.passMinutesPh}"`);
  ok(first.oldHourField === false, 'the hour-only per-pass field is still on the card');
  const quiet = await passCheck(page);
  ok(quiet.valid && quiet.noteHidden && quiet.note === '', `an untouched pair must raise nothing: ${JSON.stringify(quiet)}`);
  ok(first.perDay === '' && first.perDayPh === '10000', `per day: value "${first.perDay}", placeholder "${first.perDayPh}"`);
  ok(first.burst === '' && first.burstPh === '2000', `at once: value "${first.burst}", placeholder "${first.burstPh}"`);
  ok(first.action === 'captcha_only', `default action: ${first.action}`);

  // A figure below its window's minutes never leaves the page.  4 every 5
  // minutes; then the window alone, against the placeholder figure (500 every
  // 501 minutes); then the figure alone, against the placeholder window (59
  // every 60).  Each time the field is red, the note carries both numbers,
  // and the submit is held by the browser (no navigation, no request).
  let posts = 0;
  const countPost = (req) => { if (req.method() === 'POST' && /\/settings\/save/.test(req.url())) posts++; };
  page.on('request', countPost);
  for (const bad of [
    { passRequests: '4', passMinutes: '5', a: '4', b: '5' },
    { passRequests: '', passMinutes: '501', a: '500', b: '501' },
    { passRequests: '59', passMinutes: '', a: '59', b: '60' },
  ]) {
    await fill(page, { enabled: true, passRequests: bad.passRequests, passMinutes: bad.passMinutes, perDay: '', burst: '', action: 'captcha_only' });
    const st = await passCheck(page);
    ok(!st.valid && st.red, `${bad.a} every ${bad.b} minutes: the figure field must be invalid and red: ${JSON.stringify(st)}`);
    ok(!st.noteHidden && st.note.includes('(' + bad.a + ')') && st.note.includes('(' + bad.b + ')'),
      `${bad.a} every ${bad.b} minutes: the note must show and carry both figures: ${JSON.stringify(st)}`);
    await page.click('form[action*="section=rate_limit"] button[type="submit"]');
    await new Promise((r) => setTimeout(r, 300));
    const still = await card(page);
    ok(!/saved=1/.test(still.path + (await page.evaluate(() => location.search))), `${bad.a} every ${bad.b} minutes: the save went through`);
  }
  ok(posts === 0, `a figure below its minutes must not be posted, saw ${posts} POST(s)`);
  page.off('request', countPost);
  // Put right, the note leaves and the field is valid again.
  await fill(page, { enabled: true, passRequests: '300', passMinutes: '5', perDay: '20000', burst: '3000', action: 'deny' });
  const fixed = await passCheck(page);
  ok(fixed.valid && fixed.noteHidden && !fixed.red, `300 every 5 minutes must stand: ${JSON.stringify(fixed)}`);

  await save(page);
  const on = await card(page);
  ok(/\/settings\/rate-limit\/$/.test(on.path), `the save landed on ${on.path}, not the rate-limit tab`);
  ok(on.enabled === true && on.passRequests === '300' && on.passMinutes === '5' && on.perDay === '20000' && on.burst === '3000' && on.action === 'deny',
    `after the save: ${JSON.stringify(on)}`);
  ok(on.banner.includes('nginx -s reload'), `turning the cap on renders a zone, so the banner asks for a reload: ${on.banner.trim()}`);
  // The pair reads as one setting: label, figure, "requests every", minutes,
  // "minutes", on one line.
  const row = await page.evaluate(() => {
    const g = document.getElementById('rl-reuse-pass');
    const r = [...g.children].map((c) => c.getBoundingClientRect());
    return {
      text: g.textContent.replace(/\s+/g, ' ').trim(),
      oneLine: r.every((b) => Math.abs((b.top + b.bottom) / 2 - (r[0].top + r[0].bottom) / 2) < 8),
      inPage: g.getBoundingClientRect().right <= document.documentElement.clientWidth,
    };
  });
  ok(row.text === 'Per pass requests every minutes', `the pair's wording: "${row.text}"`);
  ok(row.oneLine && row.inPage, `the pair must sit on one line inside the page: ${JSON.stringify(row)}`);

  await fill(page, { enabled: false, passRequests: '', passMinutes: '', perDay: '', burst: '', action: 'captcha_only' });
  await save(page);
  const off = await card(page);
  ok(off.enabled === false && off.passRequests === '' && off.passMinutes === '' && off.perDay === '' && off.burst === '',
    `switched off: ${JSON.stringify(off)}`);
  // Back to the untouched default: on, blank, captcha_only.
  await fill(page, { enabled: true, passRequests: '', passMinutes: '', perDay: '', burst: '', action: 'captcha_only' });
  await save(page);
  const back = await card(page);
  ok(back.enabled === true && back.passRequests === '' && back.passMinutes === '' && back.perDay === '' && back.burst === '' && back.action === 'captcha_only',
    `back to the default: ${JSON.stringify(back)}`);

  ok(errors.length === 0, `page error(s): ${errors.join(' | ')}`);
  await browser.close();
  if (fails.length) {
    console.log('rate-limit-reuse: FAIL');
    fails.forEach((f) => console.log('  - ' + f));
    process.exit(1);
  }
  console.log('rate-limit-reuse: OK');
})().catch((e) => {
  console.log('rate-limit-reuse: FAIL (exception)', e);
  process.exit(1);
});
