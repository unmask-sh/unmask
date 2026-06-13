-- 0005 crawler_minute: per-minute crawler-category aggregation.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_crawler_minute (
    bucket_min  BIGINT NOT NULL COMMENT 'minute bucket (unix epoch seconds / 60)',
    category    VARCHAR(16) NOT NULL COMMENT 'crawler category (search / training / agent / scraper / collector)',
    total       INT NOT NULL DEFAULT 0 COMMENT 'every request from that category in the minute',
    served      INT NOT NULL DEFAULT 0 COMMENT 'subset that was challenged (passed = total - served)',
    PRIMARY KEY (bucket_min, category),
    KEY idx_crawler_minute_min (bucket_min)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-minute crawler-category aggregation (fed by the nginx access-log pipeline)';
