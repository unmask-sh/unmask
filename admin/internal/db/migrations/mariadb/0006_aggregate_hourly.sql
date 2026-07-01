-- 0006 aggregate_hourly: per-hour rollup of unmask_event for the stats page.
-- See the sqlite counterpart for the rationale and the bucket_kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_aggregate_hourly (
    bucket_hour  VARCHAR(13) NOT NULL COMMENT 'YYYY-MM-DD HH (DB clock, from date_created)',
    bucket_kind  VARCHAR(16) NOT NULL COMMENT 'rollup family: fnl (verdict x phase) / lf0 (load, flags=0) / srl (serve, rl=1)',
    bucket_key   VARCHAR(128) NOT NULL COMMENT 'key within the family (e.g. <vid>|<verdict>|<phase>)',
    cnt          BIGINT NOT NULL DEFAULT 0 COMMENT 'event count in the bucket',
    PRIMARY KEY (bucket_hour, bucket_kind, bucket_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour rollup of unmask_event for the stats page';
