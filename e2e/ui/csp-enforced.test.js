// The admin under its enforced Content-Security-Policy.
//
// script-src names the response's nonce and nothing else, so
// a <script> a template forgot to mark, an inline on* handler or a
// javascript: link does not run -- and says nothing: the page looks the same
// and a button does nothing.  This walks the admin in a real browser and
// reads what only the browser knows:
//   - the pages are the routes admin/cmd/unmask/main.go registers for GET
//     under /admin/, every settings tab, and the pages before a session.  A
//     route that is neither visited nor listed below as not a page fails the
//     test, so a new page cannot go unvisited;
//   - on each one the response carries the policy with a nonce, every
//     script element carries that nonce, no element carries an on*
//     attribute, no securitypolicyviolation event fires, and the console
//     stays free of errors;
//   - the controls whose handlers a script adds, where an attribute would
//     not run, do their work: the advisor's filters, the community list's
//     mode, the user form's password question, and on the settings tabs the
//     listen mode, the stale-browser radios, the scope picker and its
//     override toggle, the theme cards' colour controls, the add / remove
//     buttons of the rate-limit zones, the Web Bot Auth operators and the
//     Privacy Pass issuers; and the country chart's flag fallback.
//
// run.sh, once the whole suite is through, also fails on any refusal the
// browser reported to the daemon (the policy's report-uri) from any test's
// pages.
//
// The test turns the Advanced switch on to reach its two tabs and saves an
// operator and an issuer there; it takes all three back before it ends.
//
// Driven by run.sh (throwaway admin). Env: UI_E2E_BASE, UI_E2E_USER,
// UI_E2E_PASS, CHROME_BIN.
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const MAIN_GO = path.join(__dirname, '..', '..', 'admin', 'cmd', 'unmask', 'main.go');

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// GET routes under /admin/ that are not pages of the admin, and why.
const NOT_A_PAGE = {
  '/admin/docs/{$}': 'a redirect to the documentation site',
  '/admin/install/{$}': 'a redirect to the documentation site',
  '/admin/settings/export': 'a download',
  '/admin/settings/custom-rules/draft': 'a fragment the Ask page puts in a dialog',
  '/admin/settings/asn/suggest': 'JSON for the ASN tab',
  '/admin/settings/geo/preview-impact': 'JSON for the country tab',
  '/admin/advisor/ai-status': 'JSON for the advisor page',
  '/admin/advisor/status': 'JSON for the advisor page',
  '/admin/hunt/ja4chain': 'JSON for the hunt page',
  '/admin/test/preview-logo': 'an image',
  '/admin/community-bans/removals': 'served by the hub only (404 here)',
  // The challenge page, with a policy of its own (challenge-csp.test.js);
  // what the admin route does to its header is checked below.
  '/admin/test/force-pow': 'the challenge page',
  '/admin/test/force-captcha': 'the challenge page',
  '/admin/test/force-pow-then-captcha': 'the challenge page',
};
// Pages a visitor without a session gets; signed in, they redirect.
const BEFORE_SESSION = ['/admin/login', '/admin/forgot-password', '/admin/reset-password'];
// The one admin route whose page is not the admin's: the deny page as nginx
// serves it, framed by the settings page, with its own unmarked script.
const DENY_PREVIEW = '/admin/test/rate-deny';

function getRoutes() {
  const src = fs.readFileSync(MAIN_GO, 'utf8');
  const re = /mux\.HandleFunc\(\s*"GET "\s*\+\s*base\s*\+\s*"(\/admin\/[^"]*)"/g;
  const out = [];
  let m;
  while ((m = re.exec(src))) out.push(m[1]);
  return out;
}

// Loads that fail without anything being wrong with the page: the challenge
// page answers 403 by design, and the theme tab frames it for its previews;
// the test index is a bare page with no icon, so the browser asks the origin
// for one.
const LOADS_THAT_FAIL = [/\/challenge\/\?/, /\/test\/site\/[^\/]+\/\?/, /\/favicon\.ico$/];

// watch: collect what the browser refuses or complains about on a page.
async function watch(page, sink) {
  await page.evaluateOnNewDocument(() => {
    window.__cspRefused = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      window.__cspRefused.push(e.effectiveDirective + ' blocked ' + (e.blockedURI || '?') +
        ' at line ' + e.lineNumber + (e.sample ? ' ' + JSON.stringify(e.sample) : ''));
    });
  });
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const at = (m.location() || {}).url || '';
    if (/^Failed to load resource/.test(m.text()) && LOADS_THAT_FAIL.some((re) => re.test(at))) return;
    sink.push('console: ' + m.text() + (at ? ' (' + at + ')' : ''));
  });
  page.on('pageerror', (e) => sink.push('pageerror: ' + e));
}

// refused: the violations the page recorded.  The page's own document only:
// the frames it holds are the challenge and deny previews, which are not the
// admin's pages and carry their own policies.
async function refused(page) {
  return page.evaluate(() => window.__cspRefused || []);
}

async function login(page) {
  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);
}

// open: one page of the walk.  Returns the response, or null.
async function open(page, sink, p, want) {
  sink.length = 0;
  let res = null;
  try {
    res = await page.goto(BASE + p, { waitUntil: 'load' });
  } catch (e) {
    fails.push(`${p}: ${e.message}`);
    return null;
  }
  // The scripts that wait for DOMContentLoaded, and the first of the page's
  // own requests.
  await sleep(250);
  const status = res.status();
  ok(status === 200, `${p}: status ${status}`);
  const csp = res.headers()['content-security-policy'] || '';
  if (want === 'deny-preview') {
    ok(csp === "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'",
      `${p}: the deny preview's policy changed: ${csp}`);
  } else {
    const m = /; script-src 'nonce-([A-Za-z0-9+\/=]{22,})' 'report-sample'; report-uri \S+\/admin\/csp-report$/.exec(csp);
    ok(m !== null, `${p}: the response does not carry the script policy: ${JSON.stringify(csp)}`);
    ok(!/unsafe-inline|unsafe-eval/.test(csp), `${p}: the policy is loosened: ${csp}`);
    ok(!res.headers()['content-security-policy-report-only'], `${p}: a report-only policy is still sent`);
    if (m) {
      // Every script element the parser saw carries the response's nonce.
      const bare = await page.evaluate((n) => Array.from(document.querySelectorAll('script'))
        .filter((s) => s.nonce !== n).map((s) => (s.id || s.className || s.src || s.textContent.trim().slice(0, 40))), m[1]);
      ok(bare.length === 0, `${p}: script(s) without the nonce: ${JSON.stringify(bare.slice(0, 5))}`);
    }
  }
  const v = await refused(page);
  ok(v.length === 0, `${p}: the policy refused: ${v.slice(0, 5).join(' | ')}`);
  ok(sink.length === 0, `${p}: ${sink.slice(0, 5).join(' | ')}`);
  // An inline handler is refused when its event fires, not when the page
  // loads, so one nobody clicks stays silent: look for the attribute itself,
  // in the document and in the rows its templates hold.
  const inline = await page.evaluate(() => {
    const out = [];
    const scan = (root) => {
      for (const el of root.querySelectorAll('*')) {
        for (const a of el.attributes) {
          if (/^on/i.test(a.name)) out.push(`<${el.localName} ${a.name}>`);
          else if (/^(href|src|action|formaction)$/i.test(a.name) && /^\s*javascript:/i.test(a.value)) out.push(`<${el.localName} ${a.name}="javascript:">`);
        }
        if (el.localName === 'template') scan(el.content);
      }
    };
    scan(document);
    return out;
  });
  ok(inline.length === 0, `${p}: inline handler(s) in the page: ${inline.slice(0, 5).join(' ')}`);
  return res;
}

// after: what an interaction left behind, checked like a page load.
async function after(page, sink, what) {
  const v = await refused(page);
  ok(v.length === 0, `${what}: the policy refused: ${v.slice(0, 5).join(' | ')}`);
  ok(sink.length === 0, `${what}: ${sink.slice(0, 5).join(' | ')}`);
  sink.length = 0;
}

async function saveForm(page, section) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'load' }),
    page.click(`form[action*="section=${section}"] button[type="submit"]`),
  ]);
  await sleep(250);
}

// advisorSettled: the advisor page computes its candidate list behind the
// page and reloads itself when the list lands.  Wait that out, so the next
// navigation is the test's own.
async function advisorSettled(page) {
  for (let i = 0; i < 240; i++) {
    let computing = true;   // also while the page is between two loads
    try { computing = await page.$('#adv-computing') !== null; } catch (e) { /* reloading */ }
    if (!computing) break;
    await sleep(500);
  }
  await sleep(300);
}

async function setAdvanced(page, on) {
  await page.goto(BASE + '/admin/settings/about/', { waitUntil: 'load' });
  const now = await page.$eval('input[name="advanced_enabled"]', (el) => el.checked);
  if (now === on) return;
  await page.click('input[name="advanced_enabled"]');
  await saveForm(page, 'about');
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1360, height: 900 },
  });

  // ---- before a session ----------------------------------------------------
  {
    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();
    const sink = [];
    await watch(page, sink);
    for (const p of BEFORE_SESSION) {
      await open(page, sink, p + (p === '/admin/reset-password' ? '?token=not-a-token' : ''));
    }
    await ctx.close();
  }

  const page = await browser.newPage();
  const sink = [];
  await watch(page, sink);
  await login(page);
  let advancedWas = null;
  try {
    // ---- the routes ----------------------------------------------------------
    const routes = getRoutes();
    ok(routes.length >= 30 && routes.includes('/admin/{$}') && routes.includes('/admin/settings/{tab}/{$}'),
      `main.go's router is not written the way this test reads it: ${routes.length} GET routes under /admin/`);

    await page.goto(BASE + '/admin/settings/about/', { waitUntil: 'load' });
    advancedWas = await page.$eval('input[name="advanced_enabled"]', (el) => el.checked);
    await setAdvanced(page, true);
    await page.goto(BASE + '/admin/settings/', { waitUntil: 'load' });
    const tabs = await page.evaluate(() => Array.from(document.querySelectorAll('.settings-nav a[href]'))
      .map((a) => (/\/admin\/settings\/([^\/?#]+)\/$/.exec(a.getAttribute('href')) || [])[1]).filter(Boolean));
    ok(tabs.length >= 20 && tabs.includes('web-bot-auth') && tabs.includes('privacy-pass') && tabs.includes('theme'),
      `the settings nav lists ${tabs.length} tabs: ${tabs.join(', ')}`);

    await page.goto(BASE + '/admin/users/', { waitUntil: 'load' });
    const editPath = await page.evaluate(() => {
      const a = document.querySelector('a[href*="/admin/users/"][href$="/edit"]');
      return a ? new URL(a.href).pathname.replace(/^.*(\/admin\/users\/)/, '$1') : '';
    });
    ok(editPath !== '', 'the users page links to no edit page');

    const pages = [];
    for (const r of routes) {
      if (r.startsWith('/admin/api/')) continue;   // JSON for the pages' scripts
      if (r in NOT_A_PAGE || BEFORE_SESSION.includes(r)) continue;
      if (r === '/admin/settings/{tab}/{$}') { tabs.forEach((t) => pages.push(`/admin/settings/${t}/`)); continue; }
      if (r === '/admin/stats/{site}/{$}') { pages.push('/admin/stats/default/'); continue; }
      if (r === '/admin/users/{id}/edit') { if (editPath) pages.push(editPath); continue; }
      const p = r.replace('{$}', '');
      if (p.includes('{')) { fails.push(`${r}: a route this test does not know how to open -- visit it, or list it in NOT_A_PAGE`); continue; }
      pages.push(p);
    }
    // A site's own record on the two tabs that take a scope: the override
    // toggle and the delete button are only there.
    const SCOPE = 'csp-e2e.example';
    pages.push(`/admin/settings/challenge/?scope=${SCOPE}`, `/admin/settings/theme/?scope=${SCOPE}`);
    for (const p of pages) await open(page, sink, p, p === DENY_PREVIEW ? 'deny-preview' : '');

    // The challenge page on the admin's test routes keeps its own policy:
    // its nonce, its worker, no framing rule and no report-uri of the admin's.
    for (const p of Object.keys(NOT_A_PAGE).filter((r) => NOT_A_PAGE[r] === 'the challenge page')) {
      const csp = await page.evaluate(async (u) => (await fetch(u, { credentials: 'same-origin' })).headers.get('content-security-policy') || '', BASE + p);
      ok(/^default-src 'self'; script-src 'self' 'nonce-[^']+'/.test(csp) && /worker-src blob:/.test(csp) && !/frame-ancestors|report-uri/.test(csp),
        `${p}: the challenge page's policy on the admin route: ${JSON.stringify(csp)}`);
    }

    // ---- the advisor's filters submit their form ------------------------------
    await page.goto(BASE + '/admin/advisor/', { waitUntil: 'load' });
    await advisorSettled(page);
    sink.length = 0;
    await Promise.all([page.waitForNavigation({ waitUntil: 'load' }), page.select('#adv-window', '6')]);
    ok(/[?&]window=6(&|$)/.test(page.url()), `advisor: choosing 6h went to ${page.url()}`);
    await advisorSettled(page);
    await Promise.all([page.waitForNavigation({ waitUntil: 'load' }), page.click('.windowbar input[name="show_dismissed"]')]);
    ok(/[?&]show_dismissed=1(&|$)/.test(page.url()), `advisor: ticking "show dismissed" went to ${page.url()}`);
    await after(page, sink, 'advisor filters');

    // ---- the community list's mode posts its form -----------------------------
    await page.goto(BASE + '/admin/community-bans/', { waitUntil: 'load' });
    sink.length = 0;
    const posted = await page.evaluate(() => {
      // Not this test's to change: catch the post instead of sending it.
      HTMLFormElement.prototype.submit = function () { window.__submitted = this.id; };
      const sel = document.getElementById('subscribe-mode-sel');
      const other = Array.from(sel.options).find((o) => !o.selected);
      sel.value = other.value;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      return window.__submitted || '';
    });
    ok(posted === 'subscribe-mode-form', `community bans: changing the mode submitted ${JSON.stringify(posted)}`);
    await after(page, sink, 'community bans mode');

    // ---- the user form asks before it changes a password ----------------------
    if (editPath) {
      await page.goto(BASE + editPath, { waitUntil: 'load' });
      sink.length = 0;
      let saves = 0;
      const count = (q) => { if (q.method() === 'POST' && q.url().includes('/admin/users/save')) saves++; };
      page.on('request', count);
      await page.type('#user-edit-form input[name="password"]', 'Csp-e2e-never-saved-1');
      await page.click('#user-edit-form button[type="submit"]');
      await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 }).catch(() => {});
      const asked = await page.$('dialog.ux-dialog[open]') !== null;
      ok(asked, 'users: a save with a password did not ask first');
      if (asked) await page.click('dialog.ux-dialog[open] .ux-dialog-actions button:not([type="submit"])');
      await sleep(300);
      page.off('request', count);
      ok(saves === 0, `users: the form was posted ${saves} time(s) behind the question`);
      ok(page.url().endsWith(editPath), `users: cancelling the question left ${page.url()}`);
      await after(page, sink, 'users edit');
    }

    // ---- network: the listen mode shows its own fields -------------------------
    await page.goto(BASE + '/admin/settings/network/', { waitUntil: 'load' });
    sink.length = 0;
    const listen = async () => page.evaluate(() => ({
      tcp: !document.querySelector('.listen-tcp').classList.contains('hidden'),
      socket: !document.querySelector('.listen-socket').classList.contains('hidden'),
    }));
    await page.click('input[name="listen_mode"][value="socket"]');
    let l = await listen();
    ok(l.socket && !l.tcp, `network: choosing the socket shows ${JSON.stringify(l)}`);
    await page.click('input[name="listen_mode"][value="tcp"]');
    l = await listen();
    ok(l.tcp && !l.socket, `network: choosing TCP shows ${JSON.stringify(l)}`);
    await after(page, sink, 'network listen mode');

    // ---- ua-filter: "manual" opens its number box, "auto" closes it ------------
    await page.goto(BASE + '/admin/settings/ua-filter/', { waitUntil: 'load' });
    sink.length = 0;
    for (const [name, id] of [['stale_chrome_src', 'stale-chrome-manual'], ['stale_firefox_src', 'stale-firefox-manual'],
      ['stale_chrome_lag_src', 'stale-chrome-lag-manual'], ['stale_firefox_lag_src', 'stale-firefox-lag-manual']]) {
      const was = await page.$eval(`input[name="${name}"]:checked`, (el) => el.value);
      const box = async () => page.evaluate((i) => ({ disabled: document.getElementById(i).disabled, focused: document.activeElement.id === i }), id);
      // Start from "auto" whatever is saved, so both clicks are changes.
      if (was !== 'auto') await page.click(`input[name="${name}"][value="auto"]`);
      await page.click(`input[name="${name}"][value="manual"]`);
      let b = await box();
      ok(!b.disabled && b.focused, `ua-filter: ${name}=manual leaves #${id} ${JSON.stringify(b)}`);
      await page.click(`input[name="${name}"][value="auto"]`);
      b = await box();
      ok(b.disabled, `ua-filter: ${name}=auto leaves #${id} ${JSON.stringify(b)}`);
      if (was !== 'auto') await page.click(`input[name="${name}"][value="manual"]`);
    }
    await after(page, sink, 'ua-filter stale radios');

    // ---- the scope picker and the override toggle, on both tabs ---------------
    for (const tab of ['challenge', 'theme']) {
      const sel = `#scope-select-${tab}`;
      await page.goto(`${BASE}/admin/settings/${tab}/?scope=${SCOPE}`, { waitUntil: 'load' });
      sink.length = 0;
      // The toggle: off disables the form's other controls, on gives them back.
      const form = async () => page.evaluate(() => {
        const cb = document.querySelector('input.override-toggle'), f = cb.closest('form');
        const others = Array.from(f.querySelectorAll('input,select,textarea,button')).filter((el) => el !== cb && el.type !== 'submit');
        return { checked: cb.checked, off: f.classList.contains('override-off'), disabled: others.filter((el) => el.disabled).length, n: others.length };
      });
      const first = await form();
      await page.click('input.override-toggle');
      const second = await form();
      await page.click('input.override-toggle');
      const third = await form();
      for (const s of [second, third]) {
        ok(s.n > 5 && s.off === !s.checked && s.disabled === (s.checked ? 0 : s.n),
          `${tab}: the override toggle ${s.checked ? 'on' : 'off'} leaves ${JSON.stringify(s)}`);
      }
      ok(second.checked !== first.checked && third.checked === first.checked, `${tab}: the override toggle did not toggle`);

      // "+ Add new host": the question, and cancelling it puts the picker back.
      const shown = await page.$eval(sel, (el) => el.value);
      await page.select(sel, '__add__');
      await page.waitForSelector('dialog.ux-dialog[open] input[type="text"]', { visible: true, timeout: 5000 }).catch(() => {});
      ok(await page.$('dialog.ux-dialog[open]') !== null, `${tab}: "add new host" did not ask for the host`);
      await page.click('dialog.ux-dialog[open] .ux-dialog-actions button:not([type="submit"])');
      await sleep(200);
      ok(await page.$eval(sel, (el) => el.value) === shown && page.url().includes(`scope=${SCOPE}`),
        `${tab}: cancelling the question left the picker on ${JSON.stringify(await page.$eval(sel, (el) => el.value))} at ${page.url()}`);
      // ...and answering it opens that host's scope.
      await page.select(sel, '__add__');
      await page.waitForSelector('dialog.ux-dialog[open] input[type="text"]', { visible: true, timeout: 5000 }).catch(() => {});
      await page.type('dialog.ux-dialog[open] input[type="text"]', 'csp-e2e-2.example');
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'load' }),
        page.click('dialog.ux-dialog[open] .ux-dialog-actions button[type="submit"]'),
      ]);
      ok(page.url().endsWith(`/admin/settings/${tab}/?scope=csp-e2e-2.example`), `${tab}: the new host went to ${page.url()}`);
      // Back to the default scope.
      await Promise.all([page.waitForNavigation({ waitUntil: 'load' }), page.select(sel, '')]);
      ok(page.url().endsWith(`/admin/settings/${tab}/`), `${tab}: choosing the default scope went to ${page.url()}`);
      await sleep(250);
      await after(page, sink, `${tab} scope picker`);
    }

    // ---- theme: a card's colour controls do not select the card ---------------
    await page.goto(BASE + '/admin/settings/theme/', { waitUntil: 'load' });
    await sleep(250);
    sink.length = 0;
    const picked = await page.evaluate(() => {
      const cur = document.getElementById('theme-input').value;
      const card = Array.from(document.querySelectorAll('.theme-card')).find((c) => c.dataset.theme !== cur && c.querySelector('.theme-colors .uc-toggle'));
      return { cur, other: card ? card.dataset.theme : '' };
    });
    ok(picked.other !== '', `theme: no second card with colour controls (current ${picked.cur})`);
    if (picked.other) {
      const card = `.theme-card[data-theme="${picked.other}"]`;
      const state = async () => page.evaluate((c) => ({
        theme: document.getElementById('theme-input').value,
        toggled: document.querySelector(c + ' .uc-toggle').checked,
      }), card);
      const before = await state();
      await page.click(card + ' .theme-colors .uc-toggle');
      const mid = await state();
      ok(mid.toggled !== before.toggled, 'theme: the colour toggle did not toggle');
      ok(mid.theme === picked.cur, `theme: a click on the card's colour controls selected the card (${mid.theme})`);
      await page.click(card + ' .theme-colors .uc-toggle');
      // The card itself still selects.
      await page.click(card + ' .theme-card-head strong');
      const end = await state();
      ok(end.theme === picked.other, `theme: a click on the card's head selected ${end.theme}, want ${picked.other}`);
    }
    await sleep(300);
    await after(page, sink, 'theme cards');

    // ---- rate-limit: the add button adds a zone row ---------------------------
    await page.goto(BASE + '/admin/settings/rate-limit/', { waitUntil: 'load' });
    sink.length = 0;
    const zones = async () => page.$$eval('#zones-tbody tr.zone-row', (r) => r.length);
    const z0 = await zones();
    await page.click('#rl-zone-add');
    ok(await zones() === z0 + 1, `rate-limit: the add button left ${await zones()} zone rows, from ${z0}`);
    await page.evaluate(() => {
      const rows = document.querySelectorAll('#zones-tbody tr.zone-row');
      const del = rows[rows.length - 1].querySelectorAll('.z-del');
      del[del.length - 1].click();   // the edit-mode ×: a new row opens in edit mode
    });
    ok(await zones() === z0, `rate-limit: removing the new row left ${await zones()} zone rows, from ${z0}`);
    await after(page, sink, 'rate-limit zones');

    // ---- Web Bot Auth / Privacy Pass: add, save, remove the saved row, save ---
    for (const t of [
      { tab: 'web-bot-auth', add: '#wba-op-add', rows: '#wba-op-rows .op-row', field: 'input[name="operator"]', value: 'csp-e2e-operator.example', more: null },
      { tab: 'privacy-pass', add: '#pp-issuer-add', rows: '#pp-issuer-rows .pp-issuer-row', field: 'input[name="pp_issuer_name"]', value: 'csp-e2e-issuer.example', more: 'textarea[name="pp_issuer_key"]' },
    ]) {
      await page.goto(`${BASE}/admin/settings/${t.tab}/`, { waitUntil: 'load' });
      sink.length = 0;
      const values = async () => page.$$eval(`${t.rows} ${t.field}`, (els) => els.map((el) => el.value));
      const n0 = (await values()).length;
      // A row the script builds, and its own remove button.
      await page.click(t.add);
      ok((await values()).length === n0 + 1, `${t.tab}: the add button left ${(await values()).length} rows, from ${n0}`);
      await page.evaluate((rows) => { const r = document.querySelectorAll(rows); r[r.length - 1].querySelector('.del-btn').click(); }, t.rows);
      ok((await values()).length === n0, `${t.tab}: removing the new row left ${(await values()).length} rows, from ${n0}`);
      // A row the server renders: save one, then remove it with its button.
      await page.click(t.add);
      await page.evaluate((rows, field, value, more) => {
        const r = document.querySelectorAll(rows), row = r[r.length - 1];
        row.querySelector(field).value = value;
        if (more) row.querySelector(more).value = 'AAAA';
      }, t.rows, t.field, t.value, t.more);
      await saveForm(page, t.tab);
      ok((await values()).includes(t.value), `${t.tab}: the saved row is not on the page: ${JSON.stringify(await values())}`);
      await page.evaluate((rows, field, value) => {
        const row = Array.from(document.querySelectorAll(rows)).find((r) => r.querySelector(field).value === value);
        if (row) row.querySelector('.del-btn').click();
      }, t.rows, t.field, t.value);
      ok(!(await values()).includes(t.value), `${t.tab}: the saved row's remove button did not remove it`);
      await saveForm(page, t.tab);
      ok(!(await values()).includes(t.value), `${t.tab}: the row is back after the save: ${JSON.stringify(await values())}`);
      await after(page, sink, t.tab);
    }

    // ---- stats: a flag that does not load falls back to the unknown one --------
    await page.goto(BASE + '/admin/stats/default/', { waitUntil: 'load' });
    sink.length = 0;
    await page.setRequestInterception(true);
    const noFlag = (q) => (q.url().endsWith('/static/flags/zz.png') ? q.abort() : q.continue());
    page.on('request', noFlag);
    const flag = await page.evaluate(async () => {
      if (typeof renderCountryChart !== 'function') return 'renderCountryChart is not there';
      const wrap = document.createElement('div');
      wrap.id = 'csp-e2e-flags';
      document.body.appendChild(wrap);
      renderCountryChart('csp-e2e-flags', [{ CountryCode: 'ZZ', Req: 1 }]);
      const img = wrap.querySelector('img.cc-flag');
      img.loading = 'eager';
      for (let i = 0; i < 50 && !/unknown\.png$/.test(img.getAttribute('src')); i++) await new Promise((r) => setTimeout(r, 100));
      return img.getAttribute('src');
    });
    ok(/\/static\/flags\/unknown\.png$/.test(flag), `stats: the flag that failed to load ended as ${JSON.stringify(flag)}`);
    page.off('request', noFlag);
    await page.setRequestInterception(false);
    // The aborted request is this test's doing.
    const rest = sink.filter((s) => !/zz\.png|net::ERR_FAILED/.test(s));
    sink.length = 0;
    sink.push(...rest);
    await after(page, sink, 'stats flag fallback');
  } catch (e) {
    fails.push('exception: ' + (e && e.stack || e));
  } finally {
    // The switch goes back to where it was, whatever happened above.
    if (advancedWas !== null) {
      try { await setAdvanced(page, advancedWas); } catch (e) { fails.push('could not put the Advanced switch back: ' + e.message); }
    }
  }

  await browser.close();
  if (fails.length) {
    console.log('csp-enforced: FAIL');
    fails.forEach((f) => console.log('  - ' + f));
    process.exit(1);
  }
  console.log('csp-enforced: OK');
})().catch((e) => {
  console.log('csp-enforced: FAIL (exception)', e);
  process.exit(1);
});
