-- 0007 aggregate_hll: HyperLogLog sketches for aggregatable distinct-IP counts.
-- See the sqlite counterpart for the rationale and the bucket_kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_aggregate_hll (
    bucket       VARCHAR(13) NOT NULL COMMENT 'YYYY-MM-DD HH (vdip, hourly) or YYYY-MM-DD (ccip, daily)',
    bucket_kind  VARCHAR(16) NOT NULL COMMENT 'vdip (distinct IP per verdict) / ccip (distinct IP per country)',
    bucket_key   VARCHAR(128) NOT NULL COMMENT 'verdict or 2-letter country code',
    sketch       BLOB NOT NULL COMMENT '1024-byte HLL register array (precision p=10)',
    PRIMARY KEY (bucket, bucket_kind, bucket_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='HyperLogLog sketches for mergeable distinct-IP counts';

-- See the sqlite counterpart: 0007 adds new aggregate kinds, so the hourly
-- rollup is rebuilt from scratch on the next AggregateHourly run.
DELETE FROM unmask_aggregate_state WHERE name = 'hourly';
DELETE FROM unmask_aggregate_hourly;
