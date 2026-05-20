-- 0003 drop legacy phase rows.
--
-- The 2026-05-18 phase rename replaced the single bv-issuance "pow" / "verify_ok"
-- phases with explicit per-route ones (bv_pow_only / bv_captcha_only /
-- bv_pow_then_captcha) plus the mid-step "pow_pass".  The "ext_*_err" beacons
-- were folded into "error" with payload.kind.  Old rows just clutter hunt /
-- dashboard queries with phases the UI no longer renders — so drop them.
DELETE FROM unmask_event WHERE phase IN (
    'pow',
    'verify_ok',
    'pow_chain',
    'pow_done',
    'bv_pow',
    'bv_chain',
    'bv_captcha',
    'ext_render_err',
    'ext_exec_err',
    'ext_unknown_provider'
);
