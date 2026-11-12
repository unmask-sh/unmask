-- 0051 crawler_site_hourly: per-hour, per-site, per-crawler aggregation.
--
-- unmask_crawler_detail_hourly counts each crawler once for the whole install.
-- An operator running many sites behind one nginx is asked, site by site and
-- day by day, how much the AI crawlers fetched, and no table could answer: the
-- access-log reader knew the host of every request it counted and dropped it
-- before the count.
--
-- This table records the same access-log stream with the site kept:
-- (site, category, crawler) instead of (category, crawler), and two more
-- counters that say what kind of request the name was on, so a report can tell
-- the crawler itself from a client wearing its name.  It sits beside the
-- install-wide table and does not replace it.  The crawler card with no site
-- picked goes on reading that one, whose rows do not multiply with the number
-- of sites; this one is read once a site is picked, and by the daily CSV.
-- Hourly, and pruned on the same window.
--
-- site     : request $host as the per-site tables bucket it (a host counted on
--            its own, or "(other)").
-- crawler  : individual crawler name (classify.LookupCrawler), capped at 48.
-- total    : every request from that crawler to that site in the hour.
-- served   : the subset that was challenged (passed = total - served).
-- verified : the subset whose client address is inside the ranges the
--            crawler's vendor publishes, as loaded when the request was
--            counted.  Only a crawler whose vendor publishes ranges can have
--            any.
-- named    : the subset the configuration let through on the crawler's name
--            alone (the condition unmask_crawler_named_hourly counts under).
CREATE TABLE IF NOT EXISTS unmask_crawler_site_hourly (
    bucket_hour INTEGER NOT NULL,            -- hour bucket (unix epoch seconds / 3600)
    site        VARCHAR(64) NOT NULL,        -- request $host as the per-site tables bucket it (a host counted on its own, or "(other)")
    category    VARCHAR(16) NOT NULL,        -- crawler category (= classify.CrawlerTagOrder)
    crawler     VARCHAR(48) NOT NULL,        -- individual crawler name (classify.LookupCrawler)
    total       INTEGER NOT NULL DEFAULT 0,  -- every request from that crawler to that site in the hour
    served      INTEGER NOT NULL DEFAULT 0,  -- subset that was challenged (passed = total - served)
    verified    INTEGER NOT NULL DEFAULT 0,  -- subset whose client address is inside the ranges the crawler's vendor publishes
    named       INTEGER NOT NULL DEFAULT 0,  -- subset the configuration let through on the crawler's name alone
    PRIMARY KEY (bucket_hour, site, category, crawler)
);
-- One site over a window is what the card and the CSV read once a site is
-- picked, and the key leads with the hour: without this every site's rows of
-- the window are walked to find one site's, and the cost of a site's view
-- grows with the number of sites.  The same (site, time) index the other
-- per-site tables carry.
CREATE INDEX IF NOT EXISTS idx_crawler_site_site_hour ON unmask_crawler_site_hourly(site, bucket_hour);
