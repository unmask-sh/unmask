// The session popover's first line says which chain was offered and, when the
// visitor met something else, what they actually got.
//
// "Something else" has a recorded answer: every CAPTCHA beacon carries
// cap_reason -- "chain" for captcha_only, "pow_then_captcha" for that chain's
// second leg, "flags_retry" for the page-side escalation the server cannot
// know at serve time.  Only the last is a departure.
//
// It used to be inferred from the timeline instead: any captcha phase on any
// chain that was not captcha_only counted as a divergence.  That announced
// "offered pow_then_captcha -> actually captcha" on sessions that ran exactly
// as served, which is the plan reported as a deviation from itself.
//
// run.sh seeds both: uiRace runs pow_then_captcha to plan, uiEsc is a pow_only
// serve escalated by flags_retry.
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

  // Open a session's popover and read its lead line.
  const leadOf = (bt) => page.evaluate(async (bt) => {
    document.querySelectorAll('.session-chain').forEach(c => {
      c.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    });
    const rows = Array.from(document.querySelectorAll(`table.events tbody tr[data-bt="${bt}"]`));
    if (!rows.length) return { missing: true };
    const rep = rows.find(r => r.style.display !== 'none');
    const chain = rep && rep.querySelector('td:nth-child(5) .session-chain');
    if (!chain) return { seeded: rows.length, noChain: true };
    // Hover, not click: clicking pins a body-level clone that outlives the
    // read, so the next session's lookup would find the previous session's
    // popover.  The hover form renders into the one shared element.
    chain.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    await new Promise(r => setTimeout(r, 400));
    const leads = document.querySelectorAll('.session-lead');
    const lead = leads.length ? leads[leads.length - 1] : null;
    return {
      seeded: rows.length,
      lead: lead ? lead.textContent.replace(/\s+/g, ' ').trim() : null,
      // The cap_reason has to reach the DOM at all, or the line below is only
      // ever exercising the legacy fallback.
      capReasons: rows.map(r => r.getAttribute('data-cap-reason')).filter(Boolean),
    };
  }, bt);

  const plan = await leadOf('uiRace');
  if (plan.missing) {
    ok(false, 'the pow_then_captcha session is not on the page -- run.sh seeding changed');
  } else if (plan.noChain) {
    ok(false, 'the pow_then_captcha session did not collapse into a chain');
  } else {
    ok(plan.capReasons.indexOf('pow_then_captcha') >= 0,
      `cap_reason never reached the row (${JSON.stringify(plan.capReasons)})`);
    ok(plan.lead && plan.lead.indexOf('pow_then_captcha') >= 0,
      `the lead does not name the offered chain: ${plan.lead}`);
    // The whole point: a chain that ends in a CAPTCHA is not surprised to find
    // one, so there is no arrow and no second verdict.
    ok(plan.lead && plan.lead.indexOf('→') < 0 && plan.lead.indexOf('->') < 0,
      `a session that ran exactly as served is reported as a divergence: ${plan.lead}`);
  }

  const esc = await leadOf('uiEsc');
  if (esc.missing) {
    ok(false, 'the escalated session is not on the page -- run.sh seeding changed');
  } else if (esc.noChain) {
    ok(false, 'the escalated session did not collapse into a chain');
  } else {
    ok(esc.capReasons.indexOf('flags_retry') >= 0,
      `the escalation reason never reached the row (${JSON.stringify(esc.capReasons)})`);
    ok(esc.lead && esc.lead.indexOf('pow_only') >= 0,
      `the lead does not name the offered chain: ${esc.lead}`);
    // And a real escalation must still be called out, or fixing the false
    // positive would have cost the signal the line exists for.
    ok(esc.lead && (esc.lead.indexOf('→') >= 0 || esc.lead.indexOf('->') >= 0),
      `a genuine escalation is not reported: ${esc.lead}`);
    ok(esc.lead && esc.lead.indexOf('captcha') >= 0,
      `the escalation does not say what the visitor met: ${esc.lead}`);
  }

  await browser.close();
  if (fails.length) {
    console.error('FAIL\n- ' + fails.join('\n- '));
    process.exit(1);
  }
  console.log('session-lead: OK');
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
