// Browser-level check that collapsing a hunt session keeps the badges that
// hang off the phase cell.
//
// The collapse rebuilds that cell from scratch (innerHTML = '') and used to
// carry only the rate-limit badge across -- and only when it happened to sit on
// the row picked as the representative, which is the LAST phase of the session
// while the badge is minted on the serve at the START.  So in the normal case
// (serve -> load -> ...) the rl badge was dropped, the LB-misconfiguration
// warning was dropped unconditionally (nothing ever re-attached it), and the
// abandon row's returned badge and reload counter went with them.
//
// run.sh seeds one session shaped exactly like that: serve carries rl_zone +
// lb_warning, abandon carries returned + reload_count, and the representative
// row is the abandon.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN.
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
    defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/hunt/?range=24h', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);

  const res = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('table.events tbody tr[data-bt="uiCollapse"]'));
    const visible = rows.filter(r => r.style.display !== 'none');
    if (!rows.length) return { missing: true };
    // The collapsed session is one visible row; its phase cell is the one the
    // collapse rebuilt.
    const rep = visible[0];
    const cell = rep ? rep.querySelector('td:nth-child(5)') : null;
    return {
      seeded: rows.length,
      visible: visible.length,
      collapsed: !!cell && !!cell.querySelector('.session-chain'),
      rl: !!(cell && cell.querySelector('.rl-badge')),
      lb: !!(cell && cell.querySelector('.lb-warn-badge')),
      ret: !!(cell && cell.querySelector('.ret-badge')),
      // Which of the pair, not just that one is there.  The badge answers a
      // question the abandon pill does not -- whether the visitor came back
      // within 30s -- and the seeded session did (returned:1), so getting the
      // polarity backwards would report a departure that never happened.
      retVariant: (function(){
        var b = cell && cell.querySelector('.ret-badge');
        if (!b) return null;
        return b.classList.contains('ret-stayed') ? 'stayed'
             : b.classList.contains('ret-gone') ? 'gone' : 'unknown';
      })(),
      retText: (function(){
        var b = cell && cell.querySelector('.ret-badge');
        return b ? b.textContent.trim() : null;
      })(),
      reload: !!(cell && cell.querySelector('.reload-badge')),
      repPhase: rep ? rep.getAttribute('data-phase') : null,
    };
  });

  if (res.missing) {
    ok(false, 'the seeded hunt session is not on the page -- run.sh seeding or the range changed');
  } else {
    ok(res.seeded === 4, `expected the 4 seeded rows, found ${res.seeded}`);
    ok(res.visible === 1, `the session should collapse to one visible row, found ${res.visible}`);
    ok(res.collapsed, 'the phase cell was not rebuilt as a session chain -- collapse did not run');
    ok(res.repPhase === 'abandon', `the representative row should be the last phase, got ${JSON.stringify(res.repPhase)}`);
    // The four badges, none of which live on the representative row.
    ok(res.rl, 'the rl:<zone> badge was dropped by the collapse');
    ok(res.lb, 'the LB-misconfiguration warning was dropped by the collapse');
    ok(res.ret, 'the abandon returned/gone badge was dropped by the collapse');
    ok(res.retVariant === 'stayed',
      `the seeded session came back within 30s but the badge says ${res.retVariant} (${res.retText})`);
    // And the badge must not simply restate the phase beside it: a label that
    // reads as a synonym of "abandon" looks like a duplicate rather than the
    // second fact it is.
    ok(res.retText && res.retText.toLowerCase() !== 'abandon',
      `the badge restates the phase instead of answering what happened next: ${res.retText}`);
    ok(res.reload, 'the reload counter was dropped by the collapse');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('hunt-collapse: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
