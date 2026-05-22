-- 0005 crawler_minute: per-minute crawler-category aggregation.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_crawler_minute (
    bucket_min  BIGINT NOT NULL,
    category    VARCHAR(16) NOT NULL,
    total       INT NOT NULL DEFAULT 0,
    served      INT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_min, category),
    KEY idx_crawler_minute_min (bucket_min)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
