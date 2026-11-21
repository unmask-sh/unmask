// The IP popover draws the flag its row draws.
//
// A row's flag comes from the page's own handler; the popover's comes from
// the lookup it fetches (/admin/api/myip).  The two disagreed for local
// addresses: the lookup left private and loopback addresses out, so a row
// showing the local-network flag opened a popover with the "??" one -- the
// same address, placed in the table and not placed in the popover over it.
//
// Each page below carries a table of addresses and wires the popover from its
// own copy of the script (the stats page, the bans list) or from the shared
// partial (the bot hunt, the realtime tab).  The popover is opened with the
// real pointer and its flag must be the row's file.  run.sh seeds loopback
// addresses and loads no GeoIP database, so a row whose flag names something
// is a local one, and a public address keeps "??" in the row and the popover
// alike.
//
// The popover's "type" line goes with the flag as well: the lookup names the
// local range (loopback here), and never calls an address public under the
// local flag -- it had only "private" and "loopback" to say otherwise, and a
// link-local address or one in the carrier-NAT range read "public".
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_SHOT_DIR.
const path = require('path');
const puppeteer = require('puppeteer-core');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// local: the page must show a local address (the seeds put one there).
const PAGES = [
  { path: '/admin/stats/?range=24h', local: true },
  { path: '/admin/hunt/?range=24h', local: true },
  { path: '/admin/live/', local: false },
  { path: '/admin/bans/', local: false },
];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(e.message));

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  // The first visible address cell of each kind: one whose flag names
  // something, one drawn with the "??" flag.  Marked, so the pointer can be
  // sent to the same element.
  const pick = () => page.evaluate(() => {
    document.querySelectorAll('[data-e2e-flag]').forEach(el => el.removeAttribute('data-e2e-flag'));
    const out = {};
    for (const el of document.querySelectorAll('.ipclick[data-ip]')) {
      const img = el.querySelector('img.flag');
      if (!img || !el.dataset.ip || el.offsetParent === null) continue;
      const m = (img.getAttribute('src') || '').match(/\/static\/flags\/([a-z]+)\.png/);
      if (!m) continue;
      const kind = m[1] === 'unknown' ? 'unknown' : 'named';
      if (out[kind]) continue;
      el.setAttribute('data-e2e-flag', kind);
      out[kind] = { ip: el.dataset.ip, flag: m[1] };
    }
    return out;
  });

  // Somewhere with no popover trigger under it, so one popover is gone
  // before the next is opened.
  const leave = async () => {
    const a = await page.evaluate(() => {
      for (const y of [6, 40, 200, 400, 600, 800]) {
        for (const x of [window.innerWidth - 6, 6]) {
          const el = document.elementFromPoint(x, y);
          if (el && !el.closest('[data-popover], .ipclick, td, th, a, button')) return { x, y };
        }
      }
      return { x: 6, y: 6 };
    });
    await page.mouse.move(a.x, a.y);
    await sleep(400); // the 150 ms grace, and margin
  };

  // Open the popover of the marked cell and read the flag in its heading.
  // gone: the page drew its table again and the marked cell left with the old
  // one (the realtime tab does, every few seconds) -- the caller picks again.
  const openOn = async (kind, ip) => {
    const at = await page.evaluate(kind => {
      const el = document.querySelector('[data-e2e-flag="' + kind + '"]');
      if (!el) return null;
      el.scrollIntoView({ block: 'center', inline: 'center' });
      const r = el.getBoundingClientRect();
      const x = r.left + Math.min(r.width / 2, 40), y = r.top + r.height / 2;
      const hit = document.elementFromPoint(x, y);
      return { x, y, onIt: !!hit && el.contains(hit) };
    }, kind);
    if (!at) return { gone: true };
    if (!at.onIt) return { err: 'the cell is not under the pointer (covered or off screen)' };
    await page.mouse.move(at.x - 3, at.y);
    await page.mouse.move(at.x, at.y);
    // 200 ms before the lookup starts, then the lookup itself (a reverse
    // lookup of up to 800 ms inside it).
    for (let i = 0; i < 50; i++) {
      await sleep(100);
      const got = await page.evaluate(kind => {
        if (!document.querySelector('[data-e2e-flag="' + kind + '"]')) return { gone: true };
        const p = document.getElementById('ip-popover');
        if (!p || getComputedStyle(p).display === 'none') return null;
        const img = p.querySelector('h3 img.flag');
        if (!img) return null;
        const m = (img.getAttribute('src') || '').match(/\/static\/flags\/([a-z]+)\.png/);
        const line = name => {
          const dt = Array.from(p.querySelectorAll('dt')).find(d => d.textContent === name);
          return dt && dt.nextElementSibling ? dt.nextElementSibling.textContent.trim() : '';
        };
        return {
          heading: p.querySelector('h3').textContent.trim(),
          flag: m ? m[1] : '',
          drawn: img.complete && img.naturalWidth > 0,
          country: line('country'),
          type: line('type'),
        };
      }, kind);
      if (got && got.gone) return got;
      if (got && got.heading === ip && got.drawn) return got;
    }
    return { err: 'no popover for it within 5 s' };
  };

  let localSeen = 0, unknownSeen = 0;
  for (const p of PAGES) {
    const resp = await page.goto(BASE + p.path, { waitUntil: 'networkidle2' });
    ok(resp.status() === 200, `${p.path}: status ${resp.status()}`);
    if (p.local) {
      ok((await pick()).named, `${p.path}: no address with a named flag on the page -- run.sh seeding changed`);
    }
    for (const kind of ['named', 'unknown']) {
      let cell = null, pop = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        cell = (await pick())[kind];
        if (!cell) break;
        pop = await openOn(kind, cell.ip);
        if (!pop.gone) break;
        await leave();
      }
      if (!cell) continue;
      if (pop.gone) {
        ok(false, `${p.path}: ${cell.ip}: the table was drawn again under the pointer three times in a row`);
      } else if (pop.err) {
        ok(false, `${p.path}: ${cell.ip} (row flag ${cell.flag}): ${pop.err}`);
      } else {
        ok(pop.flag === cell.flag,
          `${p.path}: ${cell.ip} has the ${cell.flag} flag on its row and the ${pop.flag} flag in its popover`);
        if (kind === 'named') {
          localSeen++;
          // No database in this run: a named flag is the local network's,
          // and the popover says so in words too.
          ok(cell.flag === 'xl', `${p.path}: ${cell.ip} has the ${cell.flag} flag with no GeoIP database loaded`);
          ok(/Local network/.test(pop.country) && /\(XL\)/.test(pop.country),
            `${p.path}: the popover of ${cell.ip} names its country "${pop.country}", want the local network (XL)`);
          // The seeds are loopback addresses.
          ok(pop.type === 'loopback',
            `${p.path}: the popover of ${cell.ip} says type "${pop.type}" under the local flag, want loopback`);
        } else {
          unknownSeen++;
          ok(/unavailable/.test(pop.country),
            `${p.path}: the popover of ${cell.ip} names a country ("${pop.country}") its row could not`);
          ok(pop.type === 'public',
            `${p.path}: the popover of ${cell.ip}, a public address, says type "${pop.type}"`);
        }
        // The popover over its row, for a look by eye.
        if (process.env.UI_E2E_SHOT_DIR) {
          const name = 'ip-popover-flag-' + p.path.split('/')[2] + '-' + kind + '.png';
          try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, name) }); } catch (e) {}
        }
      }
      await leave();
    }
  }
  ok(localSeen >= 2, `only ${localSeen} local address(es) were checked across the pages, want the stats page's and the hunt's`);
  ok(unknownSeen >= 1, 'no address with the "??" flag was checked on any page -- run.sh seeding changed');
  ok(pageErrors.length === 0, `page errors: ${pageErrors.join(' | ')}`);

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log(`ip-popover-flag: OK (${localSeen} local, ${unknownSeen} unplaced)`);
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
