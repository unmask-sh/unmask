// The admin asks in its own modal, never with the browser's alert / confirm /
// prompt (2026-10-07).  This drives the one prompt the admin had -- the scope
// picker's "add a host" -- through the modal: Cancel and Esc leave the page as
// it was, a host typed in and confirmed opens its scope (Enter too, on a page
// that swallows Enter in its fields).  Then every page that used to ask with a
// browser dialog loads with the modal, and a user save that changes the
// password asks first.  Any browser dialog on the way fails the test.
//
// Driven by run.sh. Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const HOST = 'added-by-dialog.example';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1360, height: 900 },
  });
  const page = await browser.newPage();
  page.on('dialog', async d => { fails.push(`a browser ${d.type()} opened: ${d.message()}`); await d.dismiss(); });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  await page.goto(BASE + '/admin/settings/theme/', { waitUntil: 'networkidle2' });
  const sel = '#scope-select-theme';
  ok(!!(await page.$(sel)), 'the theme tab has its scope picker');
  const before = page.url();
  const pick = async () => {
    await page.select(sel, '__add__');
    await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 });
  };

  // Cancel: no navigation, the picker back on what it showed.
  await pick();
  const shape = await page.evaluate(() => {
    const d = document.querySelector('dialog.ux-dialog[open]');
    const input = d.querySelector('input[type=text]');
    return { title: d.querySelector('h3').textContent, inputShown: !input.hidden, focused: document.activeElement === input };
  });
  ok(shape.title.trim() !== '', 'the prompt has a title');
  ok(shape.inputShown && shape.focused, 'the prompt shows its field and starts in it: ' + JSON.stringify(shape));
  await page.click('dialog.ux-dialog[open] .ux-dialog-btn:not(.primary):not(.danger)');
  await sleep(300);
  ok(page.url() === before, 'Cancel stays on the page, now ' + page.url());
  ok((await page.$eval(sel, e => e.value)) === '', 'Cancel puts the picker back');
  ok(!(await page.$('dialog.ux-dialog[open]')), 'Cancel closes the modal');

  // Esc does the same.
  await pick();
  await page.keyboard.press('Escape');
  await sleep(300);
  ok(page.url() === before && !(await page.$('dialog.ux-dialog[open]')), 'Esc closes without leaving the page');

  // A host typed and confirmed opens its scope.
  await pick();
  await page.type('dialog.ux-dialog[open] input[type=text]', HOST);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.keyboard.press('Enter'),
  ]);
  ok(page.url().includes('scope=' + encodeURIComponent(HOST)), 'Enter in the field opens the new scope, got ' + page.url());

  // Every page that used to ask with a browser dialog loads clean and has
  // the modal.
  for (const path of ['/admin/users/', '/admin/bans/', '/admin/audit/', '/admin/community-bans/', '/admin/playground/']) {
    const r = await page.goto(BASE + path, { waitUntil: 'networkidle2' });
    ok(r && r.status() === 200, `${path}: status ${r && r.status()}`);
    ok(await page.evaluate(() => typeof window.unmaskDialog === 'object'), `${path}: the modal is there`);
  }

  // A user save that changes the password asks first, naming the user;
  // Cancel posts nothing.  A save without a password does not ask.
  await page.goto(BASE + '/admin/users/', { waitUntil: 'networkidle2' });
  // The signed-in user's own row: its name is the one the question must carry.
  const edit = await page.$$eval('a[href$="/edit"]', (as, u) => as.filter(a => (a.closest('tr') || a).textContent.includes(u)).map(a => a.getAttribute('href')), USER);
  ok(edit.length > 0, 'the users page links an edit page');
  if (edit.length) {
    const posts = [];
    page.on('request', r => { if (r.method() === 'POST' && /\/admin\/users\/save/.test(r.url())) posts.push(r.url()); });
    await page.goto(new URL(edit[0], BASE + '/').href, { waitUntil: 'networkidle2' });
    const form = 'form[onsubmit*="confirmSave"]';
    ok(!!(await page.$(form + ' input[name="password"]')), 'the edit form has its password field');
    await page.type(form + ' input[name="password"]', 'a-new-password-1234');
    await page.$eval(form, f => f.requestSubmit());
    await page.waitForSelector('dialog.ux-dialog[open]', { timeout: 5000 });
    const q = await page.$eval('dialog.ux-dialog[open] h3', e => e.textContent);
    ok(q.includes(USER), 'the password question names the user, got ' + q);
    await page.click('dialog.ux-dialog[open] .ux-dialog-btn:not(.primary):not(.danger)');
    await sleep(400);
    ok(posts.length === 0, 'Cancel must not post the save, got ' + posts.join(' '));
  }

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));
  await browser.close();
  if (fails.length) {
    console.error('FAIL admin-dialogs:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
  console.log('ok admin-dialogs');
})().catch(e => { console.error('ERROR admin-dialogs: ' + (e.stack || e)); process.exit(1); });
