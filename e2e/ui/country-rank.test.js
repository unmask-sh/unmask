// The dashboard's country rankings: every row shows a two-letter code -- "??"
// for an address the database could not place, XL for a local one -- so the
// bars start on one line, and the popover over a row names it; over the two
// rows that are not a country it also says what the row counts.  The harness
// has no IP-geo database, so the cards are not on the page: the test feeds
// the page's own renderer four rows in a container of its own.
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
  const resp = await page.goto(BASE + '/admin/stats/', { waitUntil: 'networkidle2' });
  ok(resp && resp.status() === 200, 'stats page: HTTP ' + (resp && resp.status()));

  const ready = await page.evaluate(() => typeof renderCountryChart === 'function' && !!window.popoverPin && !!document.getElementById('help-popover'));
  ok(ready, 'the stats page defines renderCountryChart, loads popoverPin and has #help-popover');
  if (ready) {
    const r = await page.evaluate(() => {
      const wrap = document.createElement('div');
      wrap.id = 'zz-country';
      wrap.className = 'country-chart';
      wrap.style.cssText = 'width:320px;margin:5rem 1rem 1rem;padding:1rem;background:#fff;position:relative;z-index:50';
      (document.querySelector('main') || document.body).prepend(wrap);
      renderCountryChart('zz-country', [
        { CountryCode: 'JP', Req: 75282994 },
        { CountryCode: '', Req: 57427618 },
        { CountryCode: 'US', Req: 39119534 },
        { CountryCode: 'XL', Req: 3287597 },
      ]);
      const rows = [...wrap.querySelectorAll('.country-row')];
      return {
        labels: rows.map(x => x.querySelector('.cc-label span').textContent),
        barLefts: rows.map(x => Math.round(x.querySelector('.cc-bar-wrap').getBoundingClientRect().left * 10) / 10),
        flags: rows.map(x => x.querySelector('.cc-flag').getAttribute('src').split('/').pop()),
        cursors: rows.map(x => x.querySelector('.cc-label').style.cursor),
      };
    });
    ok(r.labels.join(',') === 'JP,??,US,XL', 'every row shows a two-letter code, ?? and XL for the two that are not a country: ' + r.labels.join(','));
    ok(new Set(r.barLefts).size === 1, 'every bar starts at the same x: ' + r.barLefts.join(','));
    ok(r.flags.join(',') === 'jp.png,unknown.png,us.png,xl.png', 'flags: ' + r.flags.join(','));
    ok(r.cursors.every(c => c === 'help'), 'every row, the unknown one too, offers a popover: ' + r.cursors.join(','));

    const lang = await page.evaluate(() => (document.documentElement.lang || 'ja').split('-')[0]);
    const popOver = async i => {
      await page.hover('#zz-country .country-row:nth-child(' + (i + 1) + ') .cc-label');
      await sleep(200);
      return page.evaluate(() => {
        const p = document.getElementById('help-popover');
        const cs = getComputedStyle(p);
        const shown = p.offsetWidth > 0 && p.offsetHeight > 0 && cs.display !== 'none' && cs.visibility !== 'hidden' && cs.opacity !== '0';
        return { shown, lines: p.innerText.split('\n').map(s => s.trim()).filter(Boolean) };
      });
    };

    const jp = await popOver(0);
    ok(jp.shown && jp.lines.length === 2 && jp.lines[1] === 'JP', 'a country row: its name and code, nothing more: ' + JSON.stringify(jp.lines));

    const unk = await popOver(1);
    const unkTitle = lang === 'en' ? 'Country unknown' : '国を特定できないアドレス';
    ok(unk.shown && unk.lines[0] === unkTitle && unk.lines[1] === '??' && unk.lines.length === 3 && /(database|データベース)/.test(unk.lines[2]),
      'the unknown row names itself, shows ?? and says what it counts: ' + JSON.stringify(unk.lines));
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'country-rank.png'), clip: { x: 0, y: 0, width: 760, height: 420 } }); } catch (e) {}
    }

    const xl = await popOver(3);
    const xlTitle = lang === 'en' ? 'Local address' : 'ローカルアドレス';
    ok(xl.shown && xl.lines[0] === xlTitle && xl.lines[1] === 'XL' && xl.lines.length === 3 && /10\/8/.test(xl.lines[2]) && /XL/.test(xl.lines[2]),
      'the local row names itself, shows XL and lists its ranges: ' + JSON.stringify(xl.lines));
    if (process.env.UI_E2E_SHOT_DIR) {
      try { await page.screenshot({ path: path.join(process.env.UI_E2E_SHOT_DIR, 'country-rank-local.png'), clip: { x: 0, y: 0, width: 760, height: 420 } }); } catch (e) {}
    }
  }
  ok(errors.length === 0, 'page errors: ' + errors.join(' | '));

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('country-rank: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
