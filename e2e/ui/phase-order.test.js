// Browser-level check that a session reads as the route the visitor walked --
// in the right order, with times that do not run backwards.
//
// pow_pass and the CAPTCHA it hands off to leave in the same JS tick, as two
// requests microseconds apart, and each is stamped when the server receives
// it.  Which lands first is a race the network decides, and it does invert:
// seen in production as captcha .574 against pow_pass .576, which reads as a
// CAPTCHA solved before the proof of work ran.
//
// Neither arrival time nor elapsed_ms can settle that pair -- the first is
// wrong and the second is identical for both, same tick, same millisecond.
// The beacons therefore carry the sequence number the page counted, and the
// timeline is spaced by the intervals the page measured rather than by the
// intervals the wire produced.
//
// run.sh seeds a session with exactly that shape: equal elapsed_ms, inverted
// arrival, distinguishable only by seq.
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
    const rows = Array.from(document.querySelectorAll('table.events tbody tr[data-bt="uiRace"]'));
    if (!rows.length) return { missing: true };
    const rep = rows.find(r => r.style.display !== 'none');
    const cell = rep && rep.querySelector('td:nth-child(5) .session-chain');
    if (!cell) return { seeded: rows.length, noChain: true };
    return { seeded: rows.length, chain: cell.textContent.replace(/\s+/g, ' ').trim() };
  });

  if (res.missing) {
    ok(false, 'the seeded out-of-order session is not on the page -- run.sh seeding or the range changed');
  } else if (res.noChain) {
    ok(false, `the session did not collapse into a chain (${res.seeded} rows seeded)`);
  } else {
    ok(res.seeded === 5, `expected the 5 seeded rows, found ${res.seeded}`);
    const text = res.chain;
    ['serve', 'load', 'pow', 'captcha'].forEach(p => {
      ok(text.indexOf(p) >= 0, `the chain does not mention ${p}: ${text}`);
    });
    // The point of the test: the proof of work precedes the CAPTCHA, even
    // though the CAPTCHA beacon was recorded 2ms earlier.
    const iPow = text.indexOf('pow');
    const iCap = text.indexOf('captcha');
    ok(iPow >= 0 && iCap >= 0 && iPow < iCap,
      `the chain shows the CAPTCHA before the proof of work: ${text}`);
    ok(text.indexOf('serve') >= 0 && text.indexOf('serve') < iPow,
      `the chain does not start at serve: ${text}`);
  }

  // The timeline popover, which is where the inverted clock was visible: open
  // it and read the times off it.  Ordering the rows is only half the fix --
  // an operator reading .576 above .574 is still being told the session went
  // backwards.
  const tl = await page.evaluate(async () => {
    const rep = Array.from(document.querySelectorAll('table.events tbody tr[data-bt="uiRace"]'))
      .find(r => r.style.display !== 'none');
    const chain = rep && rep.querySelector('td:nth-child(5) .session-chain');
    if (!chain) return { noChain: true };
    chain.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise(r => setTimeout(r, 300));
    const lines = Array.from(document.querySelectorAll('.session-timeline .session-line'));
    return {
      rows: lines.map(l => ({
        ts: (l.querySelector('.ts-mono') || {}).textContent || '',
        phase: (l.querySelector('.phase-pill') || {}).textContent || '',
        // Which clock this line's time came from: a leading ~ means the
        // browser's measured interval, blank means the server's own record.
        src: l.querySelector('.ts-src-client') ? 'client' : 'server',
        // Geometry, because the mark's job is to point at ONE line.  As a
        // separate flex item it inherited .session-line's .5rem gap and
        // align-items:center, which floated it above the digits and left it
        // ambiguous which row it belonged to.
        geom: (function(){
          const m = l.querySelector('.ts-src'), ts = l.querySelector('.ts-mono');
          if (!m || !ts) return null;
          const a = m.getBoundingClientRect(), b = ts.getBoundingClientRect();
          return {
            gap: Math.round(b.left - a.right),
            dy: Math.round(Math.abs((a.top + a.bottom) / 2 - (b.top + b.bottom) / 2)),
          };
        })(),
      })),
      // The legend only appears where a derived line does.
      legend: !!document.querySelector('.session-tssrc'),
    };
  });

  if (tl.noChain) {
    ok(false, 'the session chain is not clickable, so the timeline could not be read');
  } else {
    ok(tl.rows.length >= 4, `the timeline shows ${tl.rows.length} lines, expected the seeded 5`);
    const iPow = tl.rows.findIndex(r => r.phase.indexOf('pow_pass') >= 0);
    const iCap = tl.rows.findIndex(r => r.phase.indexOf('captcha') === 0);
    ok(iPow >= 0 && iCap >= 0 && iPow < iCap,
      `the timeline lists the CAPTCHA before the proof of work: ${JSON.stringify(tl.rows)}`);
    // No line may be stamped earlier than the line above it.  This is the
    // operator-visible form of the bug: two timestamps that disagree with the
    // order they are printed in.
    for (let i = 1; i < tl.rows.length; i++) {
      ok(tl.rows[i].ts >= tl.rows[i - 1].ts,
        `the timeline runs backwards at line ${i}: ${tl.rows[i - 1].ts} (${tl.rows[i - 1].phase})` +
        ` then ${tl.rows[i].ts} (${tl.rows[i].phase})`);
    }
    // The two same-tick phases were measured at the same millisecond by the
    // page, so the timeline should show them at the same millisecond -- not
    // 2ms apart, which is the delivery jitter the reconstruction removes.
    if (iPow >= 0 && iCap >= 0) {
      ok(tl.rows[iPow].ts === tl.rows[iCap].ts,
        `same-tick phases are printed 'apart': pow_pass ${tl.rows[iPow].ts} vs captcha ${tl.rows[iCap].ts}`);
      // Those two times were computed from the browser's own intervals, and
      // the timeline has to say so: an operator comparing them against an
      // access log will not find them there to the millisecond, and silence
      // about that reads as the log being wrong.
      ok(tl.rows[iPow].src === 'client' && tl.rows[iCap].src === 'client',
        `derived times are not marked as such: pow=${tl.rows[iPow].src} captcha=${tl.rows[iCap].src}`);
      ok(tl.legend, 'a derived time is shown with no legend explaining the mark');
    }
    // The mark has to read as belonging to its own line: tight against the
    // time, and on the same visual row as it.
    tl.rows.forEach((r, i) => {
      if (!r.geom) return;
      // A gap, but a small one: flush against the digits the mark and the time
      // read as a single token, and far from them it stops belonging to the
      // line.
      ok(r.geom.gap >= 1 && r.geom.gap <= 6,
        `line ${i} (${r.phase}): the mark sits ${r.geom.gap}px from its time`);
      ok(r.geom.dy <= 3, `line ${i} (${r.phase}): the mark is ${r.geom.dy}px off its time's centre`);
    });
    // The serve is the server's own event -- nothing was in transit -- so it
    // must NOT be marked, or the mark says nothing by applying to everything.
    const iServe = tl.rows.findIndex(r => r.phase.indexOf('serve') === 0);
    if (iServe >= 0) {
      ok(tl.rows[iServe].src === 'server',
        'the serve, which the server wrote itself, is marked as a browser-derived time');
    }
  }

  // The retry session: captcha, failed, captcha again.  Nothing raced here --
  // every beacon arrived in the order it was sent -- but the two attempts
  // share a phase and so share a weight, and a weight cannot say which of two
  // identical phases came after the failure between them.  Only the browser's
  // sequence can, which makes this the case that fails if seq is dropped.
  const retry = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('table.events tbody tr[data-bt="uiRetry"]'));
    if (!rows.length) return { missing: true };
    const rep = rows.find(r => r.style.display !== 'none');
    const cell = rep && rep.querySelector('td:nth-child(5) .session-chain');
    if (!cell) return { seeded: rows.length, noChain: true };
    return { seeded: rows.length, chain: cell.textContent.replace(/\s+/g, ' ').trim() };
  });

  if (retry.missing) {
    ok(false, 'the seeded retry session is not on the page -- run.sh seeding or the range changed');
  } else if (retry.noChain) {
    ok(false, `the retry session did not collapse into a chain (${retry.seeded} rows seeded)`);
  } else {
    // 'captcha' as a substring appears only on the two real CAPTCHA pills:
    // the terminal phase is shortened to bv_cap in the chain.
    const first = retry.chain.indexOf('captcha');
    const fail = retry.chain.indexOf('verify_ng');
    const second = retry.chain.indexOf('captcha', fail < 0 ? first + 1 : fail);
    ok(first >= 0 && fail > first && second > fail,
      `the retry session lost the second CAPTCHA attempt (both attempts should straddle the failure): ${retry.chain}`);
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('phase-order: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
