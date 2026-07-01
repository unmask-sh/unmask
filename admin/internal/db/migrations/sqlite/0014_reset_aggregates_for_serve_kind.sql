-- Reset the hourly aggregate so it backfills with the new per-(ua-class,
-- verdict) bucket kinds added for DailyServeByKind (= hkServeKind hourly
-- counts + hkServeIP HLL).  Same shape as 0012 / 0013 -- the aggregator
-- replays unmask_event up to the retention window at startup, so this is
-- cheap and idempotent.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
