// The dashboard's map: the outline loads, a reading with countries paints
// streams onto the canvas, an admin can set the server's position from the
// card (through the shared dialog's prompt), and an unset position says so.
//
// Env: UI_E2E_BASE, UI_E2E_USER, UI_E2E_PASS, CHROME_BIN, UI_E2E_SHOT_DIR.
const puppeteer = require('puppeteer-core');
const path = require('path');

const BASE = process.env.UI_E2E_BASE || 'http://127.0.0.1:9815/unmask';
const USER = process.env.UI_E2E_USER || 'ui-e2e';
const PASS = process.env.UI_E2E_PASS || '';
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: 1400, height: 900 },
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
  // Start from no position: the card must say so.
  await page.evaluate(async base => {
    await fetch(base + '/admin/api/map-location', { method: 'POST', credentials: 'same-origin', body: new URLSearchParams({ lat: '', lon: '', label: '' }) });
  }, BASE);
  const resp = await page.goto(BASE + '/admin/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/ status ${resp.status()}`);
  await sleep(800); // the outline fetch and the first reading

  // Painted pixels: the land is drawn, so the canvas is no longer blank.
  // Sampled over a few frames and the brightest kept: the trail fades
  // between frames, so one frame's count wobbles.
  const lit = async () => {
    let best = -1;
    for (let i = 0; i < 4; i++) {
      const n = await page.evaluate(() => {
        const cv = document.getElementById('geo'); if (!cv) return -1;
        const ctx = cv.getContext('2d'); const d = ctx.getImageData(0, 0, cv.width, cv.height).data;
        let n = 0; for (let i = 0; i < d.length; i += 16) { if (d[i] + d[i+1] + d[i+2] > 120) n++; }
        return n;
      });
      if (n > best) best = n;
      await sleep(60);
    }
    return best;
  };
  // Brightness around a country's centroid: where its dot and label go.
  const around = (lon, lat) => page.evaluate((lon, lat) => {
    const cv = document.getElementById('geo'); const ctx = cv.getContext('2d');
    const x = Math.round((lon + 180) / 360 * cv.width), y = Math.round((90 - lat) / 180 * cv.height);
    const d = ctx.getImageData(Math.max(0, x - 8), Math.max(0, y - 8), 40, 16).data;
    let sum = 0; for (let i = 0; i < d.length; i += 4) sum += d[i] + d[i+1] + d[i+2];
    return sum;
  }, lon, lat);
  const first = await page.evaluate(() => ({
    card: !!document.getElementById('geo-card'),
    hidden: (document.getElementById('geo-card') || {}).hidden,
    unsetShown: !(document.getElementById('geo-unset') || {}).hidden,
    setBtn: !!document.getElementById('geo-set'),
    w: (document.getElementById('geo') || {}).width,
  }));
  ok(first.card && !first.hidden, 'the map card is missing or hidden (the outline did not load?)');
  ok(first.unsetShown, 'with no position set the card must say so');
  ok(first.setBtn, 'the admin is not offered the position setting');
  ok(first.w > 0, 'the canvas has no size');
  const landLit = await lit();
  ok(landLit > 50, `the outline did not paint (${landLit} lit samples)`);

  // A reading with countries: sources are drawn (dots and labels), and once
  // a position is set, streams bright enough to lift the lit count.
  const feed = () => page.evaluate(() => {
    document.dispatchEvent(new CustomEvent('unmask:now', { detail: {
      countries: { JP: { n: 148, pass: 100, bypass: 3, serve: 40, deny: 5 }, US: { n: 31, pass: 10, bypass: 0, serve: 15, deny: 6 }, DE: { n: 6, pass: 6, bypass: 0, serve: 0, deny: 0 } },
      country_names: { JP: 'Japan (日本)', US: 'United States (アメリカ合衆国)', DE: 'Germany (ドイツ)' },
    } }));
  });
  const usBefore = await around(-98.5, 39.5);
  await feed(); await sleep(400);
  const top = await page.evaluate(() => document.getElementById('geo-top').textContent);
  ok(/JP 148/.test(top) && /US 31/.test(top), 'the top-sources line does not list the reading: ' + top);
  const usAfter = await around(-98.5, 39.5);
  ok(usAfter > usBefore * 1.2, `the US source did not paint (${usBefore} -> ${usAfter})`);

  // The pointer on a source opens its popover: flag, full name, the count,
  // its share and the split by outcome.  Off the sources it goes away.
  const us = await page.evaluate(() => {
    const h = (window.unmaskGeoHot ? unmaskGeoHot() : []).find(x => x.cc === 'US');
    const r = document.getElementById('geo').getBoundingClientRect();
    return h ? { x: r.left + h.x, y: r.top + h.y } : null;
  });
  ok(!!us, 'the US source has no hit area');
  if (us) {
    await page.mouse.move(us.x, us.y);
    await sleep(150);
    const pop = await page.evaluate(() => {
      const p = document.getElementById('geo-pop');
      const img = p.querySelector('img');
      return { hidden: p.hidden, text: p.textContent.replace(/\s+/g, ' '), img: img ? img.getAttribute('src') : '', cursor: getComputedStyle(document.getElementById('geo')).cursor };
    });
    ok(!pop.hidden, 'no popover on the US source');
    ok(/United States/.test(pop.text), 'the popover lacks the full name: ' + pop.text);
    ok(/us\.png$/.test(pop.img), 'the popover lacks the flag: ' + pop.img);
    for (const n of ['31', '10', '15', '6', '17%']) ok(pop.text.indexOf(n) >= 0, 'the popover lacks ' + n + ': ' + pop.text);
    ok(pop.cursor === 'pointer', 'the source does not signal it is interactive: ' + pop.cursor);
    // The sea west of Africa: nothing there.
    const off = await page.evaluate(() => { const r = document.getElementById('geo').getBoundingClientRect(); return { x: r.left + r.width * 0.44, y: r.top + r.height * 0.6 }; });
    await page.mouse.move(off.x, off.y);
    await sleep(100);
    ok(await page.evaluate(() => document.getElementById('geo-pop').hidden), 'the popover stays up off the sources');
  }
  const sourcesLit = await lit();

  // Set the position through the card's dialog: it offers the automatic
  // estimate (none here: no geo database) and the fields for a manual one.
  await page.click('#geo-set');
  await page.waitForSelector('#geo-dialog[open]', { timeout: 5000 });
  const dlg = await page.evaluate(() => ({
    autoChecked: document.getElementById('geo-mode-auto').checked,
    autoText: document.getElementById('geo-dlg-auto').textContent,
    manualDisabled: document.getElementById('geo-lat').disabled,
  }));
  ok(dlg.autoChecked && dlg.manualDisabled, 'with nothing set the dialog must start on automatic with the fields off');
  ok(dlg.autoText.length > 10, 'the automatic line is empty');
  await page.click('#geo-mode-manual');
  await page.evaluate(() => { document.getElementById('geo-lat').value = '35.68'; document.getElementById('geo-lon').value = '139.76'; document.getElementById('geo-label').value = 'Tokyo'; });
  await page.click('#geo-save');
  await sleep(700);
  const after = await page.evaluate(() => ({
    set: document.getElementById('geo-card').dataset.set,
    auto: document.getElementById('geo-card').dataset.auto,
    unsetShown: !document.getElementById('geo-unset').hidden,
    open: !!document.querySelector('#geo-dialog[open]'),
  }));
  ok(after.set === '1' && after.auto === '0', 'the manual position was not saved from the dialog: ' + JSON.stringify(after));
  ok(!after.unsetShown && !after.open, 'the unset note is still up, or the dialog still open, after setting a position');
  // A bad point is refused in the dialog, without closing it.
  await page.click('#geo-set');
  await page.waitForSelector('#geo-dialog[open]', { timeout: 5000 });
  const reopened = await page.evaluate(() => ({ manual: document.getElementById('geo-mode-manual').checked, lat: document.getElementById('geo-lat').value, label: document.getElementById('geo-label').value }));
  ok(reopened.manual && reopened.lat === '35.68' && reopened.label === 'Tokyo', 'the dialog does not reopen on the saved manual position: ' + JSON.stringify(reopened));
  await page.evaluate(() => { document.getElementById('geo-lat').value = '95'; });
  await page.click('#geo-save');
  await sleep(300);
  const refused = await page.evaluate(() => ({ err: !document.getElementById('geo-dlg-err').hidden, open: !!document.querySelector('#geo-dialog[open]') }));
  ok(refused.err && refused.open, 'a point off the globe was not refused in the dialog');
  await page.click('#geo-cancel');
  await feed(); await sleep(1200);
  const streamsLit = await lit();
  ok(streamsLit > sourcesLit, `streams did not paint after the position was set (${sourcesLit} -> ${streamsLit})`);
  // The setting survives a reload; back to automatic through the dialog
  // (nothing to work out here, so the card says the position is unknown).
  await page.reload({ waitUntil: 'networkidle2' });
  const kept = await page.evaluate(() => document.getElementById('geo-card').dataset.label);
  ok(kept === 'Tokyo', 'the position did not survive a reload: ' + kept);
  await page.click('#geo-set');
  await page.waitForSelector('#geo-dialog[open]', { timeout: 5000 });
  await page.click('#geo-mode-auto');
  await page.click('#geo-save');
  await sleep(700);
  const backAuto = await page.evaluate(() => ({ set: document.getElementById('geo-card').dataset.set, unsetShown: !document.getElementById('geo-unset').hidden }));
  ok(backAuto.set === '0' && backAuto.unsetShown, 'switching back to automatic did not clear the setting: ' + JSON.stringify(backAuto));
  await page.click('#geo-set');
  await page.waitForSelector('#geo-dialog[open]', { timeout: 5000 });
  await page.click('#geo-mode-manual');
  await page.evaluate(() => { document.getElementById('geo-lat').value = '35.68'; document.getElementById('geo-lon').value = '139.76'; document.getElementById('geo-label').value = 'Tokyo'; });
  await page.click('#geo-save');
  await sleep(700);
  const bad = await page.evaluate(async base => {
    const r = await fetch(base + '/admin/api/map-location', { method: 'POST', credentials: 'same-origin', body: new URLSearchParams({ lat: '95', lon: '0', label: '' }) });
    return { status: r.status, body: await r.json() };
  }, BASE);
  ok(bad.status === 400 && bad.body.error, 'a point off the globe was not refused: ' + JSON.stringify(bad));

  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.evaluate(() => document.getElementById('geo-card').scrollIntoView()); await sleep(1500); await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'geo-map.png') }); } catch (e) {}
  }
  // Clear the position for whichever test runs next.
  await page.evaluate(async base => {
    await fetch(base + '/admin/api/map-location', { method: 'POST', credentials: 'same-origin', body: new URLSearchParams({ lat: '', lon: '', label: '' }) });
  }, BASE);
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('geo-map: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
