-- 0005 crawler_minute: per-minute crawler-category aggregation.
--
-- Feeds the overview "crawler traffic" funnel.  In native-module mode a
-- rescued crawler is passed straight through and never lands in unmask_event,
-- so the funnel needs this separate aggregate — fed by the nginx access-log
-- pipeline (nginxlog), which sees every request including rescued ones.
--
-- category : search / training / agent / scraper / collector (classify.AICategory)
-- total    : every request from that crawler category in the minute
-- served   : the subset that did NOT pass straight through (= was challenged)
--            passed is derived as total - served.
CREATE TABLE IF NOT EXISTS unmask_crawler_minute (
    bucket_min  INTEGER NOT NULL,
    category    VARCHAR(16) NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    served      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_min, category)
);
CREATE INDEX IF NOT EXISTS idx_crawler_minute_min ON unmask_crawler_minute(bucket_min);
