// The "nginx has not reloaded" bar's "?" is the pages' shared help tip.  It
// opens on hover and closes as the pointer leaves the "?" for it, so the
// command it holds could not be selected; a click pins it as a window of its
// own -- title bar, copy button -- that stays when the pointer leaves, until
// it is closed.  Checked on a page that linked no popover assets before the
// tip became the shared one (users), then on the dashboard.
//
// The notice shows when nginx logs a configuration older than the one on
// disk, a minute or more after that one was written.  The harness renders
// one before the daemon starts; this spec waits that minute out if need be,
// feeds the daemon's log socket a line without a render id -- what nginx
// writes under a configuration from before ids -- and sees the notice; after
// its checks, a line carrying the id on disk, which clears the notice for the
// specs after this one.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, UI_E2E_CONFIG, CHROME_BIN;
// UI_E2E_SHOT_DIR for a screenshot of the pinned help.
const fs = require('fs');
const { execFileSync } = require('child_process');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CONFIG = process.env.UI_E2E_CONFIG || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const SHOT = process.env.UI_E2E_SHOT_DIR || '';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// The instance's log socket and render dir, from its config.yml.
const conf = fs.readFileSync(CONFIG, 'utf8');
const field = k => { const m = conf.match(new RegExp('^\\s*' + k + ':\\s*(\\S+)', 'm')); return m ? m[1] : ''; };
const SOCK = field('socket_path');
const RENDER_DIR = field('output_dir');

// One access-log line to the daemon, as nginx's syslog sends it.  rv is the
// render id the line carries ('' = a configuration from before ids).
function logLine(rv) {
  return '<134>' + (Date.now() / 1000).toFixed(3) +
    ' site=ui-e2e.example kind= fc=0 hp=0 ip=10.0.0.9 ja4=- hpuri=- bp=0 scheme=https cr=-' +
    (rv ? ' rv=' + rv : '') + ' ua=ui-e2e reload-notice';
}
function send(line) {
  execFileSync('python3', ['-c',
    'import socket, sys\n' +
    's = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n' +
    's.sendto(sys.argv[1].encode(), sys.argv[2])\n', line, SOCK]);
}

(async () => {
  ok(SOCK && RENDER_DIR, 'config.yml names no nginx_log.socket_path or nginx.output_dir');
  const inc = RENDER_DIR + '/http.inc';
  const idm = fs.readFileSync(inc, 'utf8').match(/log_format unmask_minimal '[^'\n]* rv=([0-9a-f]{12}) /);
  ok(!!idm, 'http.inc carries no render id');
  const current = idm ? idm[1] : '';

  // The grace: a line from an older configuration counts a minute after the
  // one on disk was written -- by the harness, or by a settings save in a
  // spec before this one.
  const wait = fs.statSync(inc).mtimeMs + 61000 - Date.now();
  if (wait > 0) await sleep(wait);
  send(logLine(''));

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1280, height: 800 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // The page, loaded until the notice is (or is not) on it: the line is
  // taken in a moment after it is sent, not before.
  const load = async (path, want) => {
    for (let i = 0; i < 10; i++) {
      const resp = await page.goto(BASE + path, { waitUntil: 'networkidle2' });
      ok(resp.status() === 200, `${path} status ${resp.status()}`);
      const has = await page.evaluate(() => !!document.getElementById('rlnote'));
      if (has === want) return true;
      await sleep(300);
    }
    return false;
  };

  for (const path of ['/admin/users/', '/admin/']) {
    ok(await load(path, true), `${path}: no reload notice although nginx logged an older configuration`);
    const st = await page.evaluate(() => {
      const bar = document.getElementById('rlnote');
      const tip = bar && bar.querySelector('.info-tip');
      const pop = tip && tip.querySelector('.info-popup');
      return {
        shown: !!bar && getComputedStyle(bar).display !== 'none',
        underHeader: !!bar && !!bar.previousElementSibling && bar.previousElementSibling.tagName === 'HEADER',
        tip: !!tip && !!pop,
        wired: !!tip && tip.dataset.pinWired === '1',
        title: tip ? tip.getAttribute('data-pin-title') || '' : '',
        assets: !!document.querySelector('script[src*="popover-pin.js?v="]') &&
                !!document.querySelector('link[href*="popover-pin.css?v="]'),
        closed: !!pop && getComputedStyle(pop).display === 'none',
      };
    });
    ok(st.shown && st.underHeader, `${path}: the notice is not shown under the header`);
    ok(st.tip, `${path}: the notice has no shared help tip`);
    ok(st.assets, `${path}: the page links no popover assets (with the build stamp)`);
    ok(st.wired, `${path}: the tip is not wired for pinning`);
    ok(/nginx/.test(st.title) && !/%s|reload_notice\./.test(st.title), `${path}: pin title "${st.title}"`);
    ok(st.closed, `${path}: the help is open before anything touched it`);

    const popState = () => page.evaluate(() => {
      const tip = document.querySelector('#rlnote .info-tip');
      const pop = tip.querySelector('.info-popup');
      return { hover: getComputedStyle(pop).display !== 'none', pinned: tip.classList.contains('pinned') };
    });
    const pinState = () => page.evaluate(() => {
      const clones = document.querySelectorAll('body > .info-popup-pinned.popover-clone');
      const c = clones[0];
      const body = c && c.querySelector('.popover-body');
      return {
        clones: clones.length,
        text: body ? body.textContent : '',
        selectable: !!body && getComputedStyle(body).userSelect !== 'none',
        title: c ? (c.querySelector('.popover-title') || {}).textContent || '' : '',
        copy: !!(c && c.querySelector('button.popover-copy')),
        cmdCopy: !!(c && c.querySelector('.popover-body button.cmd-copy')),
        close: !!(c && c.querySelector('button.popover-close')),
      };
    });

    // 1. hover opens the help; the pointer leaving the "?" closes it -- the
    //    popup hangs below the "?", so a pointer on its way to the text is
    //    already off the "?".
    const tip = await page.$('#rlnote .info-tip');
    await tip.hover();
    await sleep(150);
    ok((await popState()).hover, `${path}: hovering the "?" opened no help`);
    await page.mouse.move(4, 400);
    await sleep(150);
    ok(!(await popState()).hover, `${path}: the help stays open after the pointer left -- then the pin is not what keeps it`);

    // 2. a click pins it: a window on <body> with the command, a title, a
    //    copy button, selectable text; it stays as the pointer leaves.
    await tip.click();
    await sleep(150);
    await page.mouse.move(4, 400);
    await sleep(300);
    const pinned = await pinState();
    ok(pinned.clones === 1, `${path}: ${pinned.clones} pinned windows after a click, expected 1`);
    ok(/sudo nginx -t && sudo nginx -s reload/.test(pinned.text), `${path}: the pinned help lacks the command: "${pinned.text.slice(0, 80)}"`);
    ok(pinned.selectable, `${path}: the pinned help's text is not selectable`);
    ok(/nginx/.test(pinned.title), `${path}: the pinned window's title is "${pinned.title}"`);
    ok(pinned.copy && pinned.close, `${path}: the pinned window lacks the copy or close button`);
    ok((await popState()).pinned, `${path}: the "?" is not marked pinned`);
    if (SHOT && path === '/admin/users/') {
      await page.screenshot({ path: SHOT + '/reload-notice-pinned.png' });
    }

    // 2b. the command's own copy button travelled into the window (the clone
    //     carries the markup; the click is handled for the document): a click
    //     copies the command alone, answers with a green ✓ for a moment, and
    //     leaves the window pinned.
    ok(pinned.cmdCopy, `${path}: the pinned help has no copy button beside the command`);
    await page.click('body > .info-popup-pinned.popover-clone .popover-body button.cmd-copy');
    await sleep(150);
    const copied = await page.evaluate(() => {
      const b = document.querySelector('body > .info-popup-pinned.popover-clone .popover-body button.cmd-copy');
      return {
        ok: !!b && b.classList.contains('is-ok') && b.querySelector('.cmd-copy-glyph').textContent === '✓',
        // the label inside the button: shown while the ✓ is up, and it says
        // the copy happened rather than what a click would copy.
        label: (function(){ const p = b && b.querySelector('.cmd-copy-pop'); return p ? { shown: getComputedStyle(p).display === 'block', text: p.textContent } : null; })(),
        clones: document.querySelectorAll('body > .info-popup-pinned.popover-clone').length,
      };
    });
    ok(copied.ok, `${path}: the command's copy button gave no ✓ after a click`);
    ok(copied.label && copied.label.shown && /コピーしました|Copied/.test(copied.label.text), `${path}: the copy button's label after a click is not the 'copied' word: ${JSON.stringify(copied.label)}`);
    ok(copied.clones === 1, `${path}: ${copied.clones} pinned windows after the command copy, expected 1`);

    // 3. its close button takes it down and hands the "?" back to hover.
    await page.click('body > .info-popup-pinned.popover-clone button.popover-close');
    await sleep(150);
    const after = await pinState();
    ok(after.clones === 0, `${path}: ${after.clones} pinned windows after close`);
    ok(!(await popState()).pinned, `${path}: the "?" stays marked pinned after close`);
  }

  // nginx logs the configuration on disk: the notice goes, here and for the
  // specs after this one.
  send(logLine(current));
  ok(await load('/admin/users/', false), 'the notice stays after nginx logged the current configuration');

  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('reload-notice: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
