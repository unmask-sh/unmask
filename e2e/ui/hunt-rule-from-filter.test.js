// A ranking row has one key -- an address, a fingerprint, a network, a user
// agent -- and a rule of one condition is what the BAN and per-axis buttons
// beside it already make, so the rows carry no custom-rule link (one did,
// for a day, and widened the two content-sized cards until the UA card
// wrapped onto a line of its own).  The way to a custom rule is the filter
// bar: the active filters are the conditions, and the rows under them are
// what the rule would catch.  It opens in a new tab so the hunt keeps its
// state.
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
    // A 1920-wide screen at 125%, or a 1536-wide laptop: where the row
    // link made the UA card wrap.
    defaultViewport: { width: 1536, height: 900 },
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/admin/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER);
  await page.type('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  const resp = await page.goto(BASE + '/admin/hunt/', { waitUntil: 'networkidle2' });
  ok(resp.status() === 200, `/admin/hunt/ status ${resp.status()}`);

  const ranks = await page.evaluate(() => {
    const cards = Array.from(document.querySelectorAll('.rank-grid .rank-card')).map(c => ({
      k: c.dataset.rankCard, top: Math.round(c.getBoundingClientRect().top), w: Math.round(c.getBoundingClientRect().width),
    }));
    const ban = document.querySelector('.rank-card-ip form.js-ban-form');
    return {
      cards,
      ruleLinks: document.querySelectorAll('.rank-card a[href*="custom-rules"]').length,
      ruleEntry: !!document.querySelector('.filter-bar .cr-from-filter'),
      firstIP: ban ? ban.dataset.ip : '',
    };
  });

  // The harness has no ASN database, so its hunt shows three cards.
  ok(ranks.cards.length >= 3, `the hunt shows ${ranks.cards.length} ranking cards`);
  if (ranks.cards.length >= 3) {
    ok(new Set(ranks.cards.map(c => c.top)).size === 1, 'the ranking cards do not share one row: ' + JSON.stringify(ranks.cards));
  }
  ok(ranks.ruleLinks === 0, `${ranks.ruleLinks} ranking row(s) link to a custom rule`);
  ok(!ranks.ruleEntry, 'the filter bar offers a rule while nothing is filtered -- a rule of no conditions');
  ok(ranks.firstIP, 'no address with a BAN button in the IP ranking -- the seed changed');

  // Narrow the log to that address: the filter bar now offers the rule, with
  // the address as its condition, named after the hunt, in a new tab.
  if (ranks.firstIP) {
    await page.type('.filter-bar input[name="ip"]', ranks.firstIP);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }),
      page.click('.filter-bar button[type="submit"]'),
    ]);
    const filtered = await page.evaluate(() => {
      const a = document.querySelector('.filter-bar .cr-from-filter');
      return {
        rankings: !!document.querySelector('.rank-grid'),
        entry: !!a,
        href: a ? a.getAttribute('href') : '',
        newTab: !!a && a.getAttribute('target') === '_blank',
        text: a ? a.textContent.trim() : '',
      };
    });
    ok(!filtered.rankings, 'the rankings still show while the log is filtered');
    ok(filtered.entry, 'filtering by an address offers no rule');
    if (filtered.entry) {
      ok(filtered.href.indexOf('/admin/settings/custom-rules/?new=1') >= 0, `the rule link goes elsewhere: ${filtered.href}`);
      ok(filtered.href.indexOf('c=ip%3A' + encodeURIComponent(ranks.firstIP)) >= 0, `the rule link lacks the address as a condition: ${filtered.href}`);
      ok(filtered.href.indexOf('label=hunt%3A') >= 0, `the draft is not named after the hunt: ${filtered.href}`);
      ok(filtered.newTab, 'the rule link opens in the same tab and loses the hunt');
      ok(/↗/.test(filtered.text), `the rule link does not say it opens a new tab: "${filtered.text}"`);
    }
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('hunt-rule-from-filter: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
