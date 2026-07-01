-- 0021 crawler_detail_hourly: per-hour, per-individual-crawler aggregation.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_crawler_detail_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'hour bucket (unix epoch seconds / 3600)',
    category    VARCHAR(16) NOT NULL COMMENT 'crawler category (= classify.CrawlerTagOrder)',
    crawler     VARCHAR(48) NOT NULL COMMENT 'individual crawler name (classify.LookupCrawler)',
    total       INT NOT NULL DEFAULT 0 COMMENT 'every request from that crawler in the hour',
    served      INT NOT NULL DEFAULT 0 COMMENT 'subset that was challenged (passed = total - served)',
    PRIMARY KEY (bucket_hour, category, crawler),
    KEY idx_crawler_detail_hour (bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour per-crawler aggregation (drill-down for the crawler-traffic card)';
