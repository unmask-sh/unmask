-- 0044 crawler_named_hourly: requests passed on a crawler's name alone.
--
-- A crawler whose vendor publishes no address range is rescued by its
-- User-Agent string, and that string is free to claim.  This table counts, per
-- hour and per crawler, the requests that went through on the claim -- no
-- challenge, no pass cookie, no bypass address -- with a HyperLogLog sketch of
-- the addresses they came from.  The UA-filter tab shows each crawler's
-- "passed by name: n requests / m addresses" from it, and doctor warns when
-- the claim is being used a lot.  Install-wide and hourly, like
-- unmask_crawler_detail_hourly beside it.
--
-- crawler : individual crawler name (classify.LookupCrawler), capped at 48.
-- cnt     : requests passed on the name alone in the hour.
-- ips     : HyperLogLog sketch of their client addresses (internal/hll).
CREATE TABLE IF NOT EXISTS unmask_crawler_named_hourly (
    bucket_hour INTEGER NOT NULL,            -- hour bucket (unix epoch seconds / 3600)
    crawler     VARCHAR(48) NOT NULL,        -- individual crawler name (classify.LookupCrawler)
    cnt         INTEGER NOT NULL DEFAULT 0,  -- requests passed on the name alone in the hour
    ips         BLOB,                        -- HyperLogLog sketch of their client addresses (internal/hll)
    PRIMARY KEY (bucket_hour, crawler)
);
CREATE INDEX IF NOT EXISTS idx_crawler_named_hour ON unmask_crawler_named_hourly(bucket_hour);
