// The notice about a database update the daemon left for the operator, in a
// real browser: it is on the page, under the header; the button starts the
// update; the page says when it has finished; dismissed, it stays away.
//
// The daemon applies migrations before it listens, so it leaves an index build
// over a large events table unapplied and announces it instead -- on every
// admin page, which is this notice.  What the server renders and what the API
// answers is covered by the Go tests (internal/handlers/schema_update_test.go);
// here it is the part only a browser runs: the script that moves the notice
// into place, the confirm, the request, the reload, the elapsed time, and
// the dismissal kept in localStorage.
//
// Unlike the other tests in this directory this one brings its own daemon.
// The shared one (run.sh) serves a fully migrated database, where there is
// nothing to announce -- and an update running on it would hold the write lock
// the other tests' saves need.  The binary is the one run.sh built or was
// given: UNMASK_BIN, or "unmask" next to UI_E2E_OUT.
const puppeteer = require('puppeteer-core');
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';
const BIN = process.env.UNMASK_BIN || path.join(process.env.UI_E2E_OUT || '', '..', 'unmask');
// Rows in the events table.  Enough that the build is still running when the
// page reloads after the click on most machines; where it is not, the checks
// of the running state are skipped and the rest still holds.
const ROWS = parseInt(process.env.UI_E2E_SCHEMA_ROWS || '400000', 10);
const PASS = 'Schema-ui-e2e-' + Math.random().toString(36).slice(2, 10) + 'Aa1';

const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

async function waitFor(what, ms, fn) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + what);
    await sleep(200);
  }
}

(async () => {
  if (!fs.existsSync(BIN)) throw new Error(`no unmask binary at ${BIN} (set UNMASK_BIN)`);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'unmask-ui-schema-'));
  const port = await freePort();
  const BASE = `http://127.0.0.1:${port}/unmask`;
  const cfg = path.join(work, 'config.yml');
  const dbPath = path.join(work, 'unmask.sqlite');
  fs.mkdirSync(path.join(work, 'nginx-out'));
  // The hub URLs point at a dead local port, as in run.sh: a throwaway daemon
  // must not register with, or pull from, the production hub.
  fs.writeFileSync(cfg, `db:
  driver: sqlite
  sqlite_path: ${dbPath}
  # A millisecond: whatever the table's size, its index is one to leave.
  schema_update_defer_seconds: 0.001
secret:
  bv_secret: "ui-e2e-schema-secret-1"
  captcha_secret_base: "ui-e2e-schema-secret-2"
server:
  bind: 127.0.0.1
  port: ${port}
  base_path: /unmask
nginx_log:
  socket_path: ${work}/log.sock
nginx:
  output_dir: ${work}/nginx-out
  sync_hub_url: "http://127.0.0.1:9/bypass-iprange-all.json"
  browser_majors_hub_url: "http://127.0.0.1:9/browser-majors.json"
community_bans:
  register_url: "http://127.0.0.1:9/register"
  submit_url: "http://127.0.0.1:9/submit"
  feed_url: "http://127.0.0.1:9/list.json"
  aggregate_url: "http://127.0.0.1:9/aggregate"
`);
  const env = Object.assign({}, process.env, { UNMASK_NO_PRIVDROP: '1' });
  const cli = (...args) => execFileSync(BIN, [...args, '-config', cfg], { env, encoding: 'utf8' });
  cli('migrate');
  execFileSync(BIN, ['user', 'create', 'schema-su', '-role', 'superadmin', '-password', PASS, '-config', cfg], { env });
  execFileSync(BIN, ['user', 'create', 'schema-viewer', '-role', 'viewer', '-password', PASS, '-config', cfg], { env });
  // The database of an install upgraded across the index migration: the index
  // gone, its migrations unrecorded.  The table is filled with its indexes off
  // and they are put back afterwards, which is what keeps this quick.
  execFileSync('python3', ['-c', `
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
idx = c.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL").fetchall()
for name, _ in idx:
    c.execute('DROP INDEX "%s"' % name)
c.execute("""WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
INSERT INTO unmask_event (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, phase, payload_json, date_created)
SELECT 'ui-e2e.example', '', 'https', 443, x'c6336407', 'UI-E2E-schema/1.0',
       't13d' || printf('%04d', i % 977) || 'h2_uie2e0000000_uie2e0000000', 'ok',
       CASE i % 10 WHEN 0 THEN 'load' WHEN 1 THEN 'bv_pow_only' ELSE 'serve' END,
       '{"bt":"uischema' || i || '","orig_path":"/articles/' || i || '/","pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}',
       strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || (i % 400000) || ' seconds') FROM n""", (int(sys.argv[2]),))
for name, sql in idx:
    if name != 'idx_unmask_event_ja4_phase':
        c.execute(sql)
c.execute("DELETE FROM schema_migrations WHERE version IN (32, 33)")
c.execute("DELETE FROM unmask_maint_state WHERE name IN ('schema_update', 'schema_rate')")
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
`, dbPath, String(ROWS)]);
  ok(/waits for you/.test(cli('migrate', '-status')), 'the seeded database does not have an update waiting');

  const log = fs.openSync(path.join(work, 'serve.log'), 'w');
  const daemon = spawn(BIN, ['serve', '-config', cfg], { env, stdio: ['ignore', log, log] });
  let browser;
  const finish = async (code) => {
    if (browser) await browser.close().catch(() => {});
    daemon.kill('SIGTERM');
    await sleep(300);
    if (code !== 0) {
      // What the daemon and the run said, where a failing CI job shows it:
      // the artifacts of a run on someone else's machine cannot be opened.
      try {
        const tail = fs.readFileSync(path.join(work, 'serve.log'), 'utf8').split('\n')
          .filter(l => /schema|migrate|db:|panic|fatal/i.test(l)).slice(-30);
        console.error('--- the daemon\'s log (schema update lines) ---\n' + tail.join('\n'));
        console.error('--- unmask migrate -status ---\n' + cli('migrate', '-status'));
      } catch (e) { /* best effort */ }
    }
    if (code !== 0 && process.env.UI_E2E_OUT) {
      // Kept where run.sh collects the artifacts of a failing test.
      try { fs.copyFileSync(path.join(work, 'serve.log'), path.join(process.env.UI_E2E_OUT, 'schema-update-serve.log')); } catch (e) { /* best effort */ }
    }
    fs.rmSync(work, { recursive: true, force: true });
    process.exit(code);
  };

  try {
    await waitFor('the daemon', 30000, async () => {
      if (daemon.exitCode !== null) throw new Error('the daemon exited at startup');
      try { const r = await fetch(BASE + '/healthz'); return r.status === 200; } catch (e) { return false; }
    });

    browser = await puppeteer.launch({
      executablePath: CHROME, headless: 'new', args: ['--no-sandbox', '--disable-gpu'],
    });
    const errors = [];
    const login = async (user, lang, width) => {
      const ctx = await browser.createBrowserContext();
      const p = await ctx.newPage();
      await p.setViewport({ width, height: 900 });
      p.on('pageerror', e => errors.push(`${user}: ${e.message}`));
      await p.setCookie({ name: 'unmask_locale', value: lang, url: BASE + '/' },
        { name: 'unmask_tz', value: 'Asia/Tokyo', url: BASE + '/' });
      await p.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
      await p.type('input[name="username"]', user);
      await p.type('input[name="password"]', PASS);
      await Promise.all([
        p.waitForNavigation({ waitUntil: 'networkidle2' }),
        p.click('button[type="submit"], input[type="submit"]'),
      ]);
      return p;
    };
    const notice = p => p.evaluate(() => {
      const el = document.getElementById('schup');
      if (!el || el.hidden) return null;
      const r = el.getBoundingClientRect();
      const h = document.querySelector('header').getBoundingClientRect();
      return {
        state: el.getAttribute('data-state'),
        text: el.querySelector('.schup-msg').innerText.replace(/\s+/g, ' ').trim(),
        buttons: Array.from(el.querySelectorAll('button')).map(b => b.id),
        gap: Math.round(r.top - h.bottom),
        inHeader: !!el.closest('header'),
        width: Math.round(r.width), pageWidth: document.documentElement.clientWidth,
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        rawKey: /schema_update\.[a-z_]+/.test(el.innerText),
      };
    });

    // ---- waiting: on every page, under the header, across the page ----------
    const su = await login('schema-su', 'en', 1280);
    for (const pagePath of ['/admin/', '/admin/hunt/', '/admin/stats/', '/admin/settings/', '/admin/bans/']) {
      await su.goto(BASE + pagePath, { waitUntil: 'networkidle2' });
      const n = await notice(su);
      if (!n) { ok(false, `${pagePath}: the notice is not on the page`); continue; }
      ok(n.state === 'pending', `${pagePath}: state ${n.state}, want pending`);
      ok(!n.inHeader && n.gap === 0, `${pagePath}: the notice belongs directly under the header (gap ${n.gap}px, inside the header: ${n.inHeader})`);
      ok(n.width === n.pageWidth, `${pagePath}: the notice is ${n.width}px wide on a ${n.pageWidth}px page`);
      ok(!n.overflowX, `${pagePath}: the page scrolls sideways with the notice on it`);
      ok(!n.rawKey, `${pagePath}: a raw translation key is shown: ${n.text}`);
      ok(n.buttons.join() === 'schup-run', `${pagePath}: buttons ${JSON.stringify(n.buttons)}, want the run button alone`);
      ok(/A database update is waiting \(expected to take .+\)\./.test(n.text), `${pagePath}: the notice does not say how long: ${n.text}`);
    }
    const vw = await login('schema-viewer', 'ja', 1280);
    const nv = await notice(vw);
    ok(nv && nv.state === 'pending', 'viewer: the notice is for everyone who signs in');
    ok(nv && nv.buttons.length === 0, `viewer: buttons ${JSON.stringify(nv && nv.buttons)}; starting the update is the superadmin's`);
    ok(nv && /データベースの更新があります/.test(nv.text) && /superadmin/.test(nv.text), `viewer (ja): ${nv && nv.text}`);

    // ---- the button --------------------------------------------------------
    await su.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
    let asked = '';
    su.once('dialog', d => { asked = d.message(); d.accept(); });
    const clicked = Date.now();
    await Promise.all([
      su.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }),   // the script reloads the page
      su.click('#schup-run'),
    ]);
    ok(/Start the database update\?/.test(asked), `the click asked ${JSON.stringify(asked)}; it must confirm first`);
    let n = await notice(su);
    ok(n && (n.state === 'running' || n.state === 'done'),
      `after the click the notice says ${n ? n.state + ': ' + n.text : 'nothing (it is not on the page)'}`);
    const sawRunning = !!(n && n.state === 'running');
    if (sawRunning) {
      ok(n.buttons.join() === 'schup-cancel', `running: buttons ${JSON.stringify(n.buttons)}, want cancel alone`);
      const e1 = await su.$eval('#schup-elapsed', e => e.textContent);
      await sleep(2200);
      const e2 = await su.$eval('#schup-elapsed', e => e.textContent).catch(() => null);
      ok(/^\d+:\d\d elapsed$/.test(e1), `running: elapsed reads ${JSON.stringify(e1)}`);
      // Gone means the page has reloaded into "done" meanwhile, which is fine.
      ok(e2 === null || e2 !== e1, `running: the elapsed time stands still at ${e1}`);
      // Anyone else sees it running too, without a button.
      await vw.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
      const r = await notice(vw);
      ok(r && (r.state !== 'running' || r.buttons.length === 0), `viewer, running: buttons ${JSON.stringify(r && r.buttons)}`);
      // A change made meanwhile is answered at once, with the reason.
      const held = await su.evaluate(async base => {
        const t0 = Date.now();
        const r = await fetch(base + '/admin/api/notify/test', { method: 'POST', credentials: 'same-origin' });
        return { status: r.status, body: await r.text(), ms: Date.now() - t0 };
      }, BASE);
      if (held.status === 503) {
        ok(/schema_update_running/.test(held.body), `a change during the update: body ${held.body}`);
        ok(held.ms < 2000, `a change during the update took ${held.ms}ms to be refused`);
      }
    } else {
      console.log(`   (the build finished before the page reloaded, ${Date.now() - clicked}ms after the click: running state not observed)`);
    }

    // ---- finished: the page says so by itself ------------------------------
    // Not a bare wait for "done": a run that failed, or a notice that went
    // away without a word, would sit out the whole timeout and say nothing
    // of what the page showed instead.
    let gone = 0;
    await waitFor('the notice to say the update finished', 180000, async () => {
      const cur = await notice(su).catch(() => undefined);   // undefined: the page is reloading
      if (cur === undefined) return false;
      if (cur && cur.state === 'done') return true;
      if (cur && cur.state === 'failed') throw new Error('the update failed: ' + cur.text);
      if (cur === null && ++gone > 20) throw new Error('the notice went away without saying that the update finished');
      return false;
    });
    n = await notice(su);
    ok(n && /The database update finished \(.+\)\./.test(n.text), `done: ${n && n.text}`);
    ok(n && n.buttons.join() === 'schup-dismiss', `done: buttons ${JSON.stringify(n && n.buttons)}`);
    ok(/up to date/.test(cli('migrate', '-status')), 'the update the page reports as finished is still pending');

    // ---- dismissed: it stays away, in this browser -------------------------
    await su.click('#schup-dismiss');
    ok((await notice(su)) === null, 'the dismissed notice is still shown');
    await su.goto(BASE + '/admin/hunt/', { waitUntil: 'networkidle2' });
    ok((await notice(su)) === null, 'the dismissed notice is back on the next page');
    await vw.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
    const other = await notice(vw);
    ok(other && other.state === 'done', 'another browser, which did not dismiss it, should still be told the update finished');

    ok(errors.length === 0, 'script errors: ' + errors.join(' | '));
    if (fails.length) { console.error('FAIL\n- ' + fails.join('\n- ')); await finish(1); }
    console.log(`schema-update: OK (${ROWS} rows; running state ${sawRunning ? 'observed' : 'not observed'})`);
    await finish(0);
  } catch (e) {
    console.error('ERROR', e.message);
    if (fails.length) console.error('before that:\n- ' + fails.join('\n- '));
    await finish(1);
  }
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
