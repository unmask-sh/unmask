-- 0021 crawler_detail_hourly: per-hour, per-individual-crawler aggregation.
--
-- unmask_crawler_minute aggregates crawler traffic into the ~11 broad
-- CrawlerTagOrder categories (search-engine, ai-training, ...).  The dashboard
-- card shows those category totals, but operators want the breakdown WITHIN a
-- category -- "search-engine = Googlebot 10000 + Bingbot 5000 + ...".  That
-- needs the individual crawler identity, which the category aggregate discards.
--
-- This table records the same access-log stream resolved one level finer:
-- (category, crawler) instead of just (category).  It is hourly (not per-minute
-- like crawler_minute) to keep the row count bounded -- the drill-down popover
-- only ever shows window totals, so minute resolution would be wasted rows.
-- Install-wide (no site dimension), matching crawler_minute.
--
-- crawler : individual crawler name (classify.LookupCrawler -- "Googlebot",
--           "Bingbot", ...), capped at 48 chars; "other" when the category
--           matched but no individual pattern did.
-- total   : every request from that crawler in the hour.
-- served  : the subset that was challenged (passed = total - served).
CREATE TABLE IF NOT EXISTS unmask_crawler_detail_hourly (
    bucket_hour INTEGER NOT NULL,            -- hour bucket (unix epoch seconds / 3600)
    category    VARCHAR(16) NOT NULL,        -- crawler category (= classify.CrawlerTagOrder)
    crawler     VARCHAR(48) NOT NULL,        -- individual crawler name (classify.LookupCrawler)
    total       INTEGER NOT NULL DEFAULT 0,  -- every request from that crawler in the hour
    served      INTEGER NOT NULL DEFAULT 0,  -- subset that was challenged (passed = total - served)
    PRIMARY KEY (bucket_hour, category, crawler)
);
CREATE INDEX IF NOT EXISTS idx_crawler_detail_hour ON unmask_crawler_detail_hourly(bucket_hour);
