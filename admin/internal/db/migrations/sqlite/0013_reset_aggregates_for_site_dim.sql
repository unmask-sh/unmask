-- Reset the hourly aggregate so it backfills with the new per-site bucket
-- kinds (= hkSiteAll / hkSiteServe / hkSiteBV / hkSiteIP).  AggregateHourly
-- replays the whole retention window from unmask_event at startup, so this is
-- the same shape as 0012's UTC reset -- cheap and idempotent.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
