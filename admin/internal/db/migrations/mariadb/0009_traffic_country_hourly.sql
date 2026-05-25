-- 0009 traffic_country_hourly: per-hour request counts split by client
-- country.  See the sqlite counterpart for the rationale and the kind
-- catalogue.
CREATE TABLE IF NOT EXISTS unmask_traffic_country_hourly (
    bucket_hour BIGINT NOT NULL,
    site        VARCHAR(64) NOT NULL,
    country     VARCHAR(2) NOT NULL,
    kind        VARCHAR(16) NOT NULL,
    cnt         BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_hour, site, country, kind),
    KEY idx_traffic_country_hourly_bucket (bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
