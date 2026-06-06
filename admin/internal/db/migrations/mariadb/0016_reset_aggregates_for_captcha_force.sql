-- Reset the hourly aggregate so it backfills with the new per-reason captcha
-- force counts + distinct-IP sketches (= hkCaptchaForce / hkCaptchaForceIP)
-- added for the CaptchaForceBreakdown card.  Same shape as 0012 / 0013 /
-- 0014 / 0015.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
