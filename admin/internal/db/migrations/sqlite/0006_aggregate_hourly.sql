-- 0006 aggregate_hourly: per-hour rollup of unmask_event for the stats page.
--
-- The stats dashboard's funnel / captcha-force / flags cards are window-total
-- aggregations (24h / 7d / 30d).  Scanning raw unmask_event on every page load
-- is O(rows-in-window), and pure-Go SQLite (modernc) runs that row processing
-- ~10x slower than the C build, so a busy 24h window (~25k rows) costs a few
-- hundred ms per card.  This table holds hourly COUNT rollups so the default
-- (no host / no site filter) stats view sums a few hundred rows instead of
-- tens of thousands.
--
-- Populated incrementally by the admin's in-process aggregator
-- (dashboard.AggregateHourly), which advances unmask_aggregate_state
-- name='hourly'.  cnt is accumulated (+=), so the aggregator is the single
-- writer; a rebuild = delete the state row + truncate this table.
--
-- bucket_hour : 'YYYY-MM-DD HH' (database clock, formatted from date_created)
-- bucket_kind : fnl -> key '<vid>|<verdict>|<phase>'  funnel verdict x phase
--               lf0 -> key '<vid>|<verdict>'          phase=load, flags=0
--               srl -> key '<vid>|<verdict>'          phase=serve, payload rl=1
-- cnt         : event count in the bucket
CREATE TABLE IF NOT EXISTS unmask_aggregate_hourly (
    bucket_hour  VARCHAR(13) NOT NULL,        -- 'YYYY-MM-DD HH' (DB clock, from date_created)
    bucket_kind  VARCHAR(16) NOT NULL,        -- rollup family: fnl (verdict x phase) / lf0 (load, flags=0) / srl (serve, rl=1)
    bucket_key   VARCHAR(128) NOT NULL,       -- key within the family (e.g. '<vid>|<verdict>|<phase>')
    cnt          INTEGER NOT NULL DEFAULT 0,  -- event count in the bucket
    PRIMARY KEY (bucket_hour, bucket_kind, bucket_key)
);
