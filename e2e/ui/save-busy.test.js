// A button that sends a form says so (2026-10-25): once a post leaves, the
// button that sent it spins and every button of that form is disabled until
// the next page.  This holds a real settings save in flight and looks at its
// button; then, on forms built in the page and answered 204 (the page stays),
// it checks the rules the shim keeps: the button's name=value still goes out,
// a post already on its way is not sent twice, a page back from the cache gets
// its buttons back, an icon-only button shows the spinner in the icon's place,
// a submit the confirm modal holds leaves the buttons alone until OK, a GET
// form is not touched, a script's unmaskBusy.submit spins the form's button,
// and on/off give back only what they took.
//
// While a navigation is held, Chrome answers no evaluate at all (neither
// puppeteer's nor a CDP session's) until the request is let go; so the held
// save is looked at by the page itself, which writes what it saw to
// sessionStorage for the next page to hand over.  The probe posts are
// answered 204 at once, the page stays, and the buttons are read after.
// The page is driven through a CDP session's Runtime.evaluate, which does not
// wait on puppeteer's idea of which document is current.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const PROBE = '/admin/__busy_probe';
const SAVE = 'form[action*="section=performance"] button[type="submit"]';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (fn, ms = 3000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return true; await sleep(50); }
  return false;
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  // The login page has no header_tools; it carries the shim on its own.
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  ok(await page.evaluate(() => typeof window.unmaskBusy === 'object'), 'the login page carries the shim');
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"]'),
  ]);

  // run(fn, ...args): fn evaluated in the document showing now.
  const cdp = await page.createCDPSession();
  const run = async (fn, ...args) => {
    const r = await cdp.send('Runtime.evaluate', {
      expression: '(' + fn.toString() + ')(' + args.map(a => JSON.stringify(a)).join(',') + ')',
      returnByValue: true, awaitPromise: true,
    });
    if (r.exceptionDetails) throw new Error('in the page: ' + ((r.exceptionDetails.exception || {}).description || r.exceptionDetails.text));
    return r.result.value;
  };
  const busyOf = sel => run(sel => {
    const b = document.querySelector(sel);
    return b && { busy: b.classList.contains('ux-busy'), solo: b.classList.contains('ux-busy-solo'), disabled: b.disabled,
      aria: b.getAttribute('aria-busy'), spin: getComputedStyle(b, '::before').animationName };
  }, sel);

  // Every post is recorded; one the test holds stays in flight until it is
  // released; the probe path is answered 204, which leaves the page as it is.
  let hold = null;
  let held = null;
  const posts = [];
  await page.setRequestInterception(true);
  page.on('request', req => {
    const u = req.url();
    if (req.method() === 'POST') posts.push({ url: u, body: req.postData() || '' });
    if (req.method() === 'POST' && hold && hold(u)) { held = req; return; }
    if (u.includes(PROBE)) return req.respond({ status: 204, body: '' });
    return req.continue();
  });

  // 1) A real save, held in flight.
  await page.goto(BASE + '/admin/settings/performance/', { waitUntil: 'networkidle2' });
  ok(await run(sel => !!document.querySelector(sel), SAVE), 'the performance tab has its save button');
  await run(sel => {
    sessionStorage.removeItem('ux-busy-seen');
    const b = document.querySelector(sel);
    new MutationObserver(() => {
      if (!b.classList.contains('ux-busy')) return;
      sessionStorage.setItem('ux-busy-seen', JSON.stringify({ busy: true, disabled: b.disabled,
        aria: b.getAttribute('aria-busy'), spin: getComputedStyle(b, '::before').animationName }));
    }).observe(b, { attributes: true });
  }, SAVE);
  hold = u => u.includes('/admin/settings/save?section=performance');
  await run(sel => document.querySelector(sel).click(), SAVE);
  ok(await until(() => held !== null), 'the save post went out');
  ok(held && /(^|&)_csrf=/.test(held.postData() || ''), 'the held save still carries its CSRF field');
  await sleep(300);
  hold = null;
  if (held) {
    const r = held; held = null;
    await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), r.continue()]);
  }
  ok(page.url().includes('saved=1'), 'the save landed, now ' + page.url());
  const st = JSON.parse(await run(() => sessionStorage.getItem('ux-busy-seen')) || 'null');
  ok(st && st.busy && st.disabled && st.aria === 'true', 'the save button spun and was disabled while its post was in flight: ' + JSON.stringify(st));
  ok(st && st.spin === 'ux-busy-spin', 'the spinner turned: ' + JSON.stringify(st));
  await run(() => sessionStorage.removeItem('ux-busy-seen'));
  ok(await run(() => !document.querySelector('.ux-busy')), 'the page after the save has no spinning button');

  // 2) Forms built in the page, posting to the probe.
  const action = new URL(BASE).pathname.replace(/\/$/, '') + PROBE;
  const build = o => run((o, action) => {
    const old = document.getElementById('bp'); if (old) old.remove();
    const f = document.createElement('form');
    f.id = 'bp'; f.method = o.method || 'post'; f.action = action;
    if (o.confirm) f.setAttribute('data-confirm', 'Post the probe?');
    f.innerHTML = '<input name="v" value="1">'
      + '<button type="submit" name="op" value="save" id="bp-save">Save</button>'
      + '<button type="submit" name="op" value="other" id="bp-other">Other</button>'
      + '<button type="submit" name="op" value="icon" id="bp-icon"><svg viewBox="0 0 10 10" width="10" height="10"><circle cx="5" cy="5" r="4"/></svg></button>';
    document.body.appendChild(f);
  }, o, action);
  const state = () => run(() => ['bp-save', 'bp-other', 'bp-icon'].map(id => {
    const b = document.getElementById(id);
    return { id, busy: b.classList.contains('ux-busy'), solo: b.classList.contains('ux-busy-solo'), disabled: b.disabled };
  }));
  const click = async sel => ok(await run(sel => { const el = document.querySelector(sel); if (el) el.click(); return !!el; }, sel), 'nothing to click at ' + sel);
  const probes = () => posts.filter(p => p.url.includes(PROBE));

  // The button that sent it spins, the others are held, and its name=value
  // is in the post: the buttons are disabled only after the form was read.
  await build({});
  let n = probes().length;
  await click('#bp-other');
  ok(await until(() => probes().length === n + 1), 'the probe post went out');
  await until(async () => (await busyOf('#bp-other')).busy);
  let s = await state();
  ok(s[1].busy && s[1].disabled, 'the button that sent the form spins: ' + JSON.stringify(s[1]));
  ok(!s[0].busy && s[0].disabled && !s[2].busy && s[2].disabled, 'the form\'s other buttons are held, without the spinner: ' + JSON.stringify(s));
  ok(probes().length > n && /(^|&)op=other(&|$)/.test(probes()[n].body), 'the sending button\'s name=value went out: ' + JSON.stringify(probes()[n]));

  // A post already on its way is not sent again.
  n = probes().length;
  await run(() => document.getElementById('bp').requestSubmit());
  await sleep(300);
  ok(probes().length === n, 'a second submit while the first is on its way posts nothing');

  // Back from the back/forward cache: the buttons are given back.
  await run(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  s = await state();
  ok(s.every(b => !b.busy && !b.disabled), 'a page back from the cache has its buttons back: ' + JSON.stringify(s));
  n = probes().length;
  await click('#bp-save');
  ok(await until(() => probes().length === n + 1), 'and the form posts again');

  // An icon-only button: the spinner in the icon's place.
  await build({});
  await click('#bp-icon');
  await until(async () => (await busyOf('#bp-icon')).busy);
  const icon = await run(() => {
    const b = document.getElementById('bp-icon');
    return { solo: b.classList.contains('ux-busy-solo'), svg: getComputedStyle(b.querySelector('svg')).display };
  });
  ok(icon.solo && icon.svg === 'none', 'an icon-only button shows the spinner instead of its icon: ' + JSON.stringify(icon));

  // Held by the confirm modal: nothing spins while it asks, nor after Cancel.
  const modalOpen = () => until(() => run(() => !!document.querySelector('dialog.ux-dialog[open]')), 5000);
  await build({ confirm: true });
  n = probes().length;
  await click('#bp-save');
  ok(await modalOpen(), 'the confirm modal opens');
  await sleep(200);
  s = await state();
  ok(s.every(b => !b.busy && !b.disabled), 'nothing spins while the confirm asks: ' + JSON.stringify(s));
  await click('dialog.ux-dialog[open] .ux-dialog-btn:not(.primary):not(.danger)');
  await sleep(300);
  s = await state();
  ok(probes().length === n && s.every(b => !b.busy && !b.disabled), 'Cancel posts nothing and leaves the buttons: ' + JSON.stringify(s));
  // OK: the post goes out, the button that asked spins.
  await click('#bp-save');
  ok(await modalOpen(), 'the confirm modal opens again');
  await click('dialog.ux-dialog[open] .ux-dialog-btn.primary, dialog.ux-dialog[open] .ux-dialog-btn.danger');
  ok(await until(() => probes().length === n + 1), 'OK posts the form');
  await until(async () => (await busyOf('#bp-save')).busy);
  s = await state();
  ok(s[0].busy && s[0].disabled, 'after OK the button that asked spins: ' + JSON.stringify(s[0]));
  ok(probes().length > n && /(^|&)op=save(&|$)/.test(probes()[n].body), 'after OK its name=value went out: ' + JSON.stringify(probes()[n]));

  // A GET form (a filter, a search) is not touched.
  await build({ method: 'get' });
  await click('#bp-save');
  await sleep(400);
  s = await state();
  ok(s.every(b => !b.busy && !b.disabled), 'a GET form keeps its buttons: ' + JSON.stringify(s));

  // A form a script held behind its own dialog: unmaskBusy.submit posts it
  // with its first button spinning.
  await build({});
  n = probes().length;
  await run(() => window.unmaskBusy.submit(document.getElementById('bp')));
  ok(await until(() => probes().length === n + 1), 'unmaskBusy.submit posts the form');
  s = await state();
  ok(s[0].busy && s[0].disabled && s[1].disabled && !s[1].busy, 'unmaskBusy.submit spins the form\'s first button and holds the rest: ' + JSON.stringify(s));

  // on / off for a save that goes through fetch: off gives back only what
  // on took.
  const onoff = await run(() => {
    const a = document.createElement('button'); a.type = 'button'; a.textContent = 'Fetch save';
    const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Already off'; b.disabled = true;
    document.body.appendChild(a); document.body.appendChild(b);
    unmaskBusy.on(a); unmaskBusy.on(b);
    const during = [a.classList.contains('ux-busy') && a.disabled, b.classList.contains('ux-busy') && b.disabled];
    unmaskBusy.off(a); unmaskBusy.off(b);
    const after = [!a.classList.contains('ux-busy') && !a.disabled && !a.hasAttribute('aria-busy'), !b.classList.contains('ux-busy') && b.disabled];
    a.remove(); b.remove();
    return { during, after };
  });
  ok(onoff.during.every(Boolean), 'on() spins and disables: ' + JSON.stringify(onoff));
  ok(onoff.after.every(Boolean), 'off() gives back what on() took, and leaves a button the page had disabled: ' + JSON.stringify(onoff));

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.error('FAIL save-busy:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok save-busy');
})().catch(e => { console.error('ERROR save-busy: ' + (e.stack || e)); process.exit(1); });
