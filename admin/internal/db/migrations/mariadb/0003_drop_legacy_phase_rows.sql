-- 0003 drop legacy phase rows.  Same content as sqlite/0003_*.sql.
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
