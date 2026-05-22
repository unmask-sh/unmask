-- 0007 aggregate_hll: HyperLogLog sketches for aggregatable distinct-IP counts.
-- See the sqlite counterpart for the rationale and the bucket_kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_aggregate_hll (
    bucket       VARCHAR(13) NOT NULL,
    bucket_kind  VARCHAR(16) NOT NULL,
    bucket_key   VARCHAR(128) NOT NULL,
    sketch       BLOB NOT NULL,
    PRIMARY KEY (bucket, bucket_kind, bucket_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- See the sqlite counterpart: 0007 adds new aggregate kinds, so the hourly
-- rollup is rebuilt from scratch on the next AggregateHourly run.
DELETE FROM unmask_aggregate_state WHERE name = 'hourly';
DELETE FROM unmask_aggregate_hourly;
