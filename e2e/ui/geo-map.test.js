// The dashboard's map: the outline loads, a reading with countries paints
// streams onto the canvas, an admin can set the server's position from the
// card (through the shared dialog's prompt), and an unset position says so.
// The legend switches what the map draws (blocked bots alone by default, the
// choice kept in the browser), and a line under it names what was refused.
// And it stays cheap: the map's canvas is painted once per reading, only the
// particles' layer moves, and nothing draws with a canvas shadow (a shadow
// blurs on every draw, and a busy install's page stalled on them).
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
  // Every canvas shadow anyone sets, from the first script on.
  await page.evaluateOnNewDocument(() => {
    const d = Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, 'shadowBlur');
    Object.defineProperty(CanvasRenderingContext2D.prototype, 'shadowBlur', {
      get() { return d.get.call(this); },
      set(v) { if (v > 0) window.__shadows = (window.__shadows || 0) + 1; d.set.call(this, v); },
    });
  });

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
  const resp = await page.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/live/ status ${resp.status()}`);
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
  // Brightness around a country's centroid: where its dot and label go.  The
  // map shows 90°N to 60°S.
  const around = (lon, lat) => page.evaluate((lon, lat) => {
    const cv = document.getElementById('geo'); const ctx = cv.getContext('2d');
    const x = Math.round((lon + 180) / 360 * cv.width), y = Math.round((90 - lat) / 150 * cv.height);
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
  // a position is set, streams bright enough to lift the lit count.  The
  // strip's own five-second poll is switched off first, or a real reading
  // (empty on this install) could land between the feed and the checks.
  await page.click('#live-toggle');
  const autoOff = await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed') === 'false');
  ok(autoOff, 'the auto-refresh switch did not go off');
  const feed = (refused) => page.evaluate(refused => {
    document.dispatchEvent(new CustomEvent('unmask:now', { detail: Object.assign({
      countries: { JP: { n: 48, pass: 30, bypass: 1, serve: 12, deny: 5, blocked: 6, people: 11 }, US: { n: 9, pass: 3, bypass: 0, serve: 4, deny: 2, blocked: 3, people: 3 } },
      countries30: { JP: { n: 148, pass: 100, bypass: 3, serve: 40, deny: 5, blocked: 13, people: 32 }, US: { n: 31, pass: 10, bypass: 0, serve: 15, deny: 6, blocked: 8, people: 13 }, DE: { n: 6, pass: 6, bypass: 0, serve: 0, deny: 0, blocked: 0, people: 0 } },
      country_names: { JP: 'Japan (日本)', US: 'United States (アメリカ合衆国)', DE: 'Germany (ドイツ)' },
    }, refused || {}) }));
  }, refused);
  const usBefore = await around(-98.5, 39.5);
  await feed(); await sleep(400);
  // Blocked bots alone by default: JP and US blocked some, DE none.
  // The line's entries, one per source (the text runs them together).
  const topItems = () => page.evaluate(() => Array.from(document.querySelectorAll('#geo-top span')).map(s => s.textContent.trim()));
  const top = await topItems();
  ok(top.includes('JP 13') && top.includes('US 8') && !top.some(t => /^DE/.test(t)), 'the top-sources line does not list the blocked bots of the reading: ' + top.join(' | '));
  const pressed = () => page.evaluate(() => Array.from(document.querySelectorAll('#geo-legend .geo-k')).filter(b => b.getAttribute('aria-pressed') === 'true').map(b => b.dataset.k).join(','));
  ok(await pressed() === 'blocked', 'the legend does not start on blocked alone: ' + await pressed());
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
      return { hidden: p.hidden, text: p.textContent.replace(/\s+/g, ' '), cells: Array.from(p.querySelectorAll('td.n')).map(td => td.textContent.trim()).join(','), img: img ? img.getAttribute('src') : '', cursor: getComputedStyle(document.getElementById('geo')).cursor };
    });
    ok(!pop.hidden, 'no popover on the US source');
    ok(/United States/.test(pop.text), 'the popover lacks the full name: ' + pop.text);
    ok(/us\.png$/.test(pop.img), 'the popover lacks the flag: ' + pop.img);
    // Every request of the source and the whole split, though the map draws
    // only the blocked: requests, last minute, then blocked / solved or left
    // / passed on a cookie / bypassed / benign crawlers.
    ok(pop.cells === '31,9,8,13,10,0,0', 'the popover figures are not the whole split: ' + pop.cells);
    ok(pop.text.indexOf('17%') >= 0, 'the popover lacks the share: ' + pop.text);
    ok(pop.cursor === 'pointer', 'the source does not signal it is interactive: ' + pop.cursor);
    // The sea west of Africa: nothing there.
    const off = await page.evaluate(() => { const r = document.getElementById('geo').getBoundingClientRect(); return { x: r.left + r.width * 0.44, y: r.top + r.height * 0.6 }; });
    await page.mouse.move(off.x, off.y);
    await sleep(100);
    ok(await page.evaluate(() => document.getElementById('geo-pop').hidden), 'the popover stays up off the sources');
  }

  // The legend's switches: passed-on-a-cookie added, every source counts its
  // blocked and its passes (DE comes in on its passes); everything off, the
  // line says nothing is switched on and no source is left to point at.
  const legendClick = k => page.click('#geo-legend .geo-k[data-k="' + k + '"]');
  await legendClick('pass'); await sleep(200);
  const both = { top: await topItems(), kept: await page.evaluate(() => localStorage.getItem('unmask:map-kinds')) };
  ok(['JP 113', 'US 18', 'DE 6'].every(t => both.top.includes(t)), 'switching passes on did not redraw the sources: ' + both.top.join(' | '));
  ok(both.kept === '["blocked","pass"]', 'the choice is not kept in the browser: ' + both.kept);
  await legendClick('pass'); await legendClick('blocked'); await sleep(200);
  const none = await page.evaluate(() => ({ top: document.getElementById('geo-top').textContent, hot: unmaskGeoHot().length }));
  ok(none.hot === 0 && none.top.length > 3 && !/JP|US/.test(none.top), 'with nothing switched on the map still draws, or says nothing: ' + JSON.stringify(none));
  await legendClick('blocked'); await sleep(200);
  ok(await pressed() === 'blocked', 'the legend did not come back to blocked alone: ' + await pressed());

  // The refusals line: each reason with its count and its busiest rules,
  // linked to the hunt page filtered on it; none in the reading says so.
  await feed({
    refused30: { asn_deny: 812, banned: 40, geo_deny: 5 },
    refused_rules30: { asn_deny: [{ rule: 'AS16509', n: 700, label: 'AS16509' }, { rule: 'AS14061', n: 112, label: 'AS14061' }], geo_deny: [{ rule: 'CN', n: 5, label: 'CN' }] },
    refused_names: { asn_deny: 'ASN deny', banned: 'Banned', geo_deny: 'Country deny' },
  });
  await sleep(200);
  const ref = await page.evaluate(() => {
    const el = document.getElementById('geo-refused');
    return { text: el.textContent.replace(/\s+/g, ' '), links: Array.from(el.querySelectorAll('a')).map(a => a.getAttribute('href')), flag: !!el.querySelector('img[src$="/cn.png"]') };
  });
  ok(/ASN deny 812/.test(ref.text) && /AS16509 700/.test(ref.text) && /AS14061 112/.test(ref.text) && /Banned 40/.test(ref.text), 'the refusals line does not list the reasons and rules: ' + ref.text);
  ok(ref.text.indexOf('ASN deny') < ref.text.indexOf('Banned') && ref.text.indexOf('Banned') < ref.text.indexOf('Country deny'), 'the reasons are not busiest first: ' + ref.text);
  ok(ref.links.length === 3 && /\/admin\/hunt\/\?range=1h&force_reason=asn_deny$/.test(ref.links[0]), 'the reasons do not link to the hunt page: ' + ref.links.join(' '));
  ok(ref.flag, 'a country rule is shown without its flag');
  await feed({ refused30: {} }); await sleep(200);
  const refNone = await page.evaluate(() => { const el = document.getElementById('geo-refused'); return { text: el.textContent, links: el.querySelectorAll('a').length }; });
  ok(refNone.links === 0 && /:\s*\S/.test(refNone.text), 'with nothing refused the line does not say so: ' + refNone.text);
  await feed(); await sleep(200);
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
  // The address-check button is offered only when no interface has a global
  // address; this host may have one, so the rule is checked, not the state.
  const probe = await page.evaluate(() => ({ src: document.getElementById('geo-card').dataset.autoSource, hidden: document.getElementById('geo-probe-wrap').hidden, label: document.getElementById('geo-probe').textContent }));
  ok(probe.hidden === (probe.src === 'interface'), 'the address-check button must show exactly when no interface has a global address: ' + JSON.stringify(probe));
  ok(probe.hidden || probe.label.length > 3, 'the address-check button has no label');
  const setLabel = await page.evaluate(() => document.getElementById('geo-set').textContent);
  ok(/:\s*\S/.test(setLabel), 'the set button does not show the current position: ' + setLabel);
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
  // A second without a reading: the particles' layer is drawn frame after
  // frame, the map under it not at all.
  const work = await page.evaluate(async () => {
    const n = { map: 0, fx: 0 };
    const count = (cv, k) => {
      const c = cv.getContext('2d');
      ['fill', 'stroke', 'drawImage', 'fillRect', 'fillText', 'clearRect'].forEach(fn => {
        const orig = c[fn]; c[fn] = function () { n[k]++; return orig.apply(this, arguments); };
      });
    };
    const fx = document.querySelector('#geo-card canvas.geo-fx');
    count(document.getElementById('geo'), 'map');
    if (fx) count(fx, 'fx');
    await new Promise(r => setTimeout(r, 1000));
    return Object.assign(n, { layer: !!fx, shadows: window.__shadows || 0 });
  });
  ok(work.layer, 'the map has no particles layer over it');
  ok(work.fx > 30, `the particles did not move (${work.fx} draws in a second)`);
  ok(work.map === 0, `the map was repainted between readings (${work.map} draws in a second)`);
  ok(work.shadows === 0, `the map drew with canvas shadows (${work.shadows} times)`);
  // The setting survives a reload, and so does the legend's choice; back to
  // automatic through the dialog (nothing to work out here, so the card says
  // the position is unknown).
  await legendClick('people'); await sleep(100);
  await page.reload({ waitUntil: 'networkidle2' });
  const kept = await page.evaluate(() => document.getElementById('geo-card').dataset.label);
  ok(kept === 'Tokyo', 'the position did not survive a reload: ' + kept);
  ok(await pressed() === 'blocked,people', 'the legend\'s choice did not survive a reload: ' + await pressed());
  await legendClick('people'); await sleep(100);
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
  // In Japanese the map is centred on Japan: the Pacific whole, the Americas
  // to the right, Europe to the left -- and the outline still paints under
  // the shifted sources.  Counts carry a thousands separator in every
  // language (JP's blocked here, what the map draws by default).
  await page.setCookie({ name: 'unmask_locale', value: 'ja', url: BASE + '/' });
  await page.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  ok(await page.evaluate(() => document.documentElement.lang) === 'ja', 'the page did not switch to Japanese');
  // The auto-refresh switch is remembered across loads (localStorage), and
  // the first pass left it off: a blind click here would turn it on, and the
  // reading that fetch brings (empty on this install) would land after the
  // one fed below and wipe it -- which is what happened on the CI runner,
  // where the fetch is slower than the feed.  Off it stays, checked.
  if (await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed') !== 'false')) await page.click('#live-toggle');
  ok(await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed') === 'false'), 'the auto-refresh switch is not off for the Japanese pass');
  await page.evaluate(() => {
    document.dispatchEvent(new CustomEvent('unmask:now', { detail: {
      countries: { JP: { n: 480, pass: 300, bypass: 10, serve: 120, deny: 50, blocked: 130, people: 40 } },
      countries30: { JP: { n: 3010, pass: 1000, bypass: 30, serve: 1900, deny: 80, blocked: 1480, people: 500 }, US: { n: 310, pass: 100, bypass: 0, serve: 150, deny: 60, blocked: 160, people: 50 }, DE: { n: 60, pass: 40, bypass: 0, serve: 20, deny: 0, blocked: 15, people: 5 } },
      country_names: { JP: 'Japan (日本)', US: 'United States (アメリカ合衆国)', DE: 'Germany (ドイツ)' },
    } }));
  });
  await page.waitForFunction(() => /JP 1,480/.test(document.getElementById('geo-top').textContent), { timeout: 5000 }).catch(() => {});
  await sleep(400);
  const ja = await page.evaluate(() => {
    const cv = document.getElementById('geo'), w = cv.getBoundingClientRect().width;
    const at = cc => (window.unmaskGeoHot ? unmaskGeoHot() : []).find(h => h.cc === cc);
    const ctx = cv.getContext('2d'), d = ctx.getImageData(0, 0, cv.width, cv.height).data;
    let lit = 0;
    for (let i = 0; i < d.length; i += 4 * 97) if (d[i] + d[i + 1] + d[i + 2] > 60) lit++;
    return { w, jp: at('JP'), us: at('US'), de: at('DE'), lit, top: document.getElementById('geo-top').textContent };
  });
  ok(ja.jp && Math.abs(ja.jp.x - ja.w / 2) < ja.w * 0.06, 'Japan is not in the middle of the Japanese map: ' + JSON.stringify(ja.jp) + ' of ' + ja.w);
  ok(ja.us && ja.jp && ja.us.x > ja.jp.x, 'the Americas are not to the right of Japan: ' + JSON.stringify([ja.jp, ja.us]));
  ok(ja.de && ja.jp && ja.de.x < ja.jp.x, 'Europe is not to the left of Japan: ' + JSON.stringify([ja.jp, ja.de]));
  ok(ja.lit > 50, `the shifted outline did not paint (${ja.lit} lit samples)`);
  ok(/JP 1,480/.test(ja.top), 'the top-sources line lacks the thousands separator: ' + ja.top);
  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.evaluate(() => document.getElementById('geo-card').scrollIntoView()); await sleep(1500); await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'geo-map-ja.png') }); } catch (e) { /* the picture is a convenience */ }
  }
  // The server's country picks the map, not the reader's language: with the
  // server in the United States the Japanese page prints Greenwich in the
  // middle, as a map printed there does -- the Americas left, Europe in the
  // middle, Japan right.
  await page.evaluate(async base => {
    await fetch(base + '/admin/api/map-location', { method: 'POST', credentials: 'same-origin', body: new URLSearchParams({ lat: '39.04', lon: '-77.49', label: 'Virginia' }) });
  }, BASE);
  await page.goto(BASE + '/admin/live/', { waitUntil: 'networkidle2' });
  if (await page.evaluate(() => document.getElementById('live-toggle').getAttribute('aria-pressed') !== 'false')) await page.click('#live-toggle');
  await page.evaluate(() => {
    document.dispatchEvent(new CustomEvent('unmask:now', { detail: {
      countries: { JP: { n: 480, pass: 300, bypass: 10, serve: 120, deny: 50, blocked: 130, people: 40 } },
      countries30: { JP: { n: 3010, pass: 1000, bypass: 30, serve: 1900, deny: 80, blocked: 1480, people: 500 }, US: { n: 310, pass: 100, bypass: 0, serve: 150, deny: 60, blocked: 160, people: 50 }, DE: { n: 60, pass: 40, bypass: 0, serve: 20, deny: 0, blocked: 15, people: 5 } },
      country_names: { JP: 'Japan (日本)', US: 'United States (アメリカ合衆国)', DE: 'Germany (ドイツ)' },
    } }));
  });
  await page.waitForFunction(() => /JP 1,480/.test(document.getElementById('geo-top').textContent), { timeout: 5000 }).catch(() => {});
  await sleep(400);
  const usMap = await page.evaluate(() => {
    const w = document.getElementById('geo').getBoundingClientRect().width;
    const at = cc => (window.unmaskGeoHot ? unmaskGeoHot() : []).find(h => h.cc === cc);
    return { w, lang: document.documentElement.lang, jp: at('JP'), us: at('US'), de: at('DE') };
  });
  ok(usMap.lang === 'ja', 'the page is not in Japanese for the US-server pass');
  ok(usMap.de && Math.abs(usMap.de.x - usMap.w * 0.53) < usMap.w * 0.06, 'Greenwich is not in the middle with the server in the United States: ' + JSON.stringify(usMap.de) + ' of ' + usMap.w);
  ok(usMap.us && usMap.de && usMap.jp && usMap.us.x < usMap.de.x && usMap.de.x < usMap.jp.x, 'the Americas, Europe and Japan are not in that order: ' + JSON.stringify([usMap.us, usMap.de, usMap.jp]));
  if (process.env.UI_E2E_SHOT_DIR) {
    try { await page.evaluate(() => document.getElementById('geo-card').scrollIntoView()); await sleep(1500); await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'geo-map-us.png') }); } catch (e) { /* the picture is a convenience */ }
  }
  await page.deleteCookie({ name: 'unmask_locale', url: BASE + '/' });

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
