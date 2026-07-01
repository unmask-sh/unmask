-- 0009 traffic_country_hourly: per-hour request counts split by client
-- country, written by the nginx-log pipeline (= the unmask_minimal access-log
-- feed) by resolving each client IP through ipgeo and folding into the hour
-- bucket.
--
-- Complements unmask_cookie_minute (= per-minute request count without
-- country) so the 30-day chart can break traffic down by country without
-- changing the per-minute cookie pipeline.
--
-- bucket_hour : unix epoch hour (time.Unix() / 3600).
-- site        : $host of the request.
-- country     : 2-letter ISO code from ipgeo; empty string when mmdb is not
--               loaded or the IP is private / unmappable.
-- kind        : same catalogue as unmask_cookie_minute:
--                 'total'            -> every request
--                 'captcha'          -> bv_kind=captcha
--                 'pow'              -> bv_kind=pow
--                 'challenge_served' -> fc=1 with empty bv_kind
-- cnt         : accumulated count for that bucket.
--
-- Written by nginxlog.Reader on each hour flush (UPSERT with cnt accumulate).
-- Pruned alongside unmask_aggregate_hourly retention.
CREATE TABLE IF NOT EXISTS unmask_traffic_country_hourly (
    bucket_hour INTEGER NOT NULL,         -- unix epoch hour (time.Unix() / 3600)
    site        VARCHAR(64) NOT NULL,     -- request $host
    country     VARCHAR(2) NOT NULL,      -- 2-letter ISO code from ipgeo (empty when unmappable / mmdb absent)
    kind        VARCHAR(16) NOT NULL,     -- total / captcha / pow / challenge_served
    cnt         INTEGER NOT NULL DEFAULT 0,  -- accumulated count for the bucket
    PRIMARY KEY (bucket_hour, site, country, kind)
);
CREATE INDEX IF NOT EXISTS idx_traffic_country_hourly_bucket
    ON unmask_traffic_country_hourly(bucket_hour);
