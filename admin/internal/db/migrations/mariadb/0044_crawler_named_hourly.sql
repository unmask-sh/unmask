-- 0044 crawler_named_hourly: requests passed on a crawler's name alone.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_crawler_named_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'hour bucket (unix epoch seconds / 3600)',
    crawler     VARCHAR(48) NOT NULL COMMENT 'individual crawler name (classify.LookupCrawler)',
    cnt         INT NOT NULL DEFAULT 0 COMMENT 'requests passed on the name alone in the hour',
    ips         BLOB COMMENT 'HyperLogLog sketch of their client addresses (internal/hll)',
    PRIMARY KEY (bucket_hour, crawler),
    KEY idx_crawler_named_hour (bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour per-crawler count of requests passed on the crawler name alone (UA-filter tab, doctor)';
