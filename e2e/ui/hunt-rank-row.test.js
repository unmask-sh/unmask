// The hunt's four ranking cards share one row, and the per-row link that
// opens a custom rule prefilled from the row must not be what pushes the
// last of them (UA) onto a line of its own.  As a text button ("Rule ↗") it
// widened the two content-sized cards (IP, JA4) by some 70px each, which at
// a common window width was the difference.  So the link is an icon no
// wider than a couple of rem, with no title= (the native bubble) and its
// label in a popover of the page's own that opens on hover.
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
    // A 1920-wide screen at 125%, or a 1536-wide laptop: the width at which
    // the text link made the UA card wrap while the four cards fitted
    // without it.
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

  const geo = await page.evaluate(() => {
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
    const cards = Array.from(document.querySelectorAll('.rank-grid .rank-card')).map(c => ({
      k: c.dataset.rankCard, top: Math.round(c.getBoundingClientRect().top), w: Math.round(c.getBoundingClientRect().width),
    }));
    const links = Array.from(document.querySelectorAll('.rank-card .cr-link'));
    return {
      rem, cards,
      links: links.length,
      widest: Math.max(0, ...links.map(a => a.getBoundingClientRect().width)),
      titled: links.filter(a => a.hasAttribute('title')).length,
      unlabelled: links.filter(a => !(a.getAttribute('aria-label') || '').trim()).length,
      newTab: links.filter(a => a.getAttribute('target') === '_blank').length,
    };
  });

  // The harness has no ASN database, so its hunt shows three cards; the
  // row check holds for whichever are there.
  ok(geo.cards.length >= 3, `the hunt shows ${geo.cards.length} ranking cards`);
  ok(geo.links > 0, 'no rule links in the rankings -- the seed left every card empty');
  if (geo.cards.length >= 3) {
    const tops = new Set(geo.cards.map(c => c.top));
    ok(tops.size === 1, 'the ranking cards do not share one row: ' + JSON.stringify(geo.cards));
  }
  if (geo.links > 0) {
    ok(geo.widest <= 2 * geo.rem, `a rule link is ${Math.round(geo.widest)}px wide -- it is meant to be an icon`);
    ok(geo.titled === 0, `${geo.titled} rule link(s) carry a title= bubble`);
    ok(geo.unlabelled === 0, `${geo.unlabelled} rule link(s) have no accessible name`);
    ok(geo.newTab === geo.links, 'a rule link opens in the same tab');
  }

  // Hovering the icon shows its label.
  if (geo.links > 0) {
    await page.hover('.rank-card .cr-link');
    const pop = await page.evaluate(() => {
      const a = document.querySelector('.rank-card .cr-link');
      const p = a.parentNode.querySelector('.cr-pop');
      const r = p ? p.getBoundingClientRect() : null;
      return { shown: !!p && getComputedStyle(p).display !== 'none' && r.width > 0, text: p ? p.textContent.trim() : '',
        inCard: !!r && r.left >= a.closest('.rank-card').getBoundingClientRect().left - 1 };
    });
    ok(pop.shown, 'hovering the rule icon shows no label');
    ok(/ルール|rule/i.test(pop.text), `the label does not say what the icon does: "${pop.text}"`);
    ok(pop.inCard, 'the label pokes out of the card on the left, where a card can clip it');
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('hunt-rank-row: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
