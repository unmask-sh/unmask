-- 0009 traffic_country_hourly: per-hour request counts split by client
-- country.  See the sqlite counterpart for the rationale and the kind
-- catalogue.
CREATE TABLE IF NOT EXISTS unmask_traffic_country_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'unix epoch hour (time.Unix() / 3600)',
    site        VARCHAR(64) NOT NULL COMMENT 'request $host',
    country     VARCHAR(2) NOT NULL COMMENT '2-letter ISO code from ipgeo (empty when unmappable / mmdb absent)',
    kind        VARCHAR(16) NOT NULL COMMENT 'total / captcha / pow / challenge_served',
    cnt         BIGINT NOT NULL DEFAULT 0 COMMENT 'accumulated count for the bucket',
    PRIMARY KEY (bucket_hour, site, country, kind),
    KEY idx_traffic_country_hourly_bucket (bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour request counts split by client country (nginx-log pipeline)';
