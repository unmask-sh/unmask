-- 0007 aggregate_hll: HyperLogLog sketches for aggregatable distinct-IP counts.
--
-- COUNT(DISTINCT ip_address) is not summable across time buckets, so the
-- stats page's per-verdict / per-country "unique IP" figures could not be
-- rolled up like the plain counts in unmask_aggregate_hourly. An HLL sketch
-- *is* mergeable: this table holds one 1024-byte sketch per bucket, and the
-- read side merges the buckets in the window and estimates.
--
-- Written incrementally by dashboard.AggregateHourly (same last_id cursor as
-- unmask_aggregate_hourly).
--
-- bucket      : 'YYYY-MM-DD HH' for vdip (hourly), 'YYYY-MM-DD' for ccip (daily)
-- bucket_kind : vdip -> key '<verdict>'        distinct IP per verdict (all phases)
--               ccip -> key '<country-code>'   distinct IP per country (phase=serve)
-- sketch      : 1024-byte HLL register array (precision p=10)
CREATE TABLE IF NOT EXISTS unmask_aggregate_hll (
    bucket       VARCHAR(13) NOT NULL,   -- 'YYYY-MM-DD HH' (vdip, hourly) or 'YYYY-MM-DD' (ccip, daily)
    bucket_kind  VARCHAR(16) NOT NULL,   -- vdip (distinct IP per verdict) / ccip (distinct IP per country)
    bucket_key   VARCHAR(128) NOT NULL,  -- verdict or 2-letter country code
    sketch       BLOB NOT NULL,          -- 1024-byte HLL register array (precision p=10)
    PRIMARY KEY (bucket, bucket_kind, bucket_key)
);

-- The 0006 aggregator produced only fnl/lf0/srl buckets; 0007 adds the per-
-- country count and the HLL sketches, so the hourly rollup must be rebuilt to
-- cover rows already aggregated under 0006. Dropping the cursor and the
-- partial counts makes dashboard.AggregateHourly do one clean full backfill on
-- its next run.
DELETE FROM unmask_aggregate_state WHERE name = 'hourly';
DELETE FROM unmask_aggregate_hourly;
