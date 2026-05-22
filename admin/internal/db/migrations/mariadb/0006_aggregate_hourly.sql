-- 0006 aggregate_hourly: per-hour rollup of unmask_event for the stats page.
-- See the sqlite counterpart for the rationale and the bucket_kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_aggregate_hourly (
    bucket_hour  VARCHAR(13) NOT NULL,
    bucket_kind  VARCHAR(16) NOT NULL,
    bucket_key   VARCHAR(128) NOT NULL,
    cnt          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_hour, bucket_kind, bucket_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
