-- Reset the hourly aggregate so it backfills with the new per-flags count +
-- distinct-IP sketches (= hkFlags / hkFlagsIP) added for the
-- FlagsDistribution card.  Same shape as 0012 / 0013 / 0014 / 0015 / 0016.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
