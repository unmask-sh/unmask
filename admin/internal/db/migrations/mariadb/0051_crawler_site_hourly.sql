-- 0051 crawler_site_hourly: per-hour, per-site, per-crawler aggregation.
-- See the sqlite counterpart for the rationale.  The (site, bucket_hour) index
-- is for a site's view, which reads one site over a window while the key leads
-- with the hour.
CREATE TABLE IF NOT EXISTS unmask_crawler_site_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'hour bucket (unix epoch seconds / 3600)',
    site        VARCHAR(64) NOT NULL COMMENT 'request $host as the per-site tables bucket it (a host counted on its own, or "(other)")',
    category    VARCHAR(16) NOT NULL COMMENT 'crawler category (= classify.CrawlerTagOrder)',
    crawler     VARCHAR(48) NOT NULL COMMENT 'individual crawler name (classify.LookupCrawler)',
    total       INT NOT NULL DEFAULT 0 COMMENT 'every request from that crawler to that site in the hour',
    served      INT NOT NULL DEFAULT 0 COMMENT 'subset that was challenged (passed = total - served)',
    verified    INT NOT NULL DEFAULT 0 COMMENT 'subset whose client address is inside the ranges the crawler''s vendor publishes',
    named       INT NOT NULL DEFAULT 0 COMMENT 'subset the configuration let through on the crawler''s name alone',
    PRIMARY KEY (bucket_hour, site, category, crawler),
    KEY idx_crawler_site_site_hour (site, bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour per-site per-crawler aggregation (the crawler card with a site picked, daily CSV)';
