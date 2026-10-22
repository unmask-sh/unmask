-- 0045 crawler_named_hourly country: where the requests passed on a crawler's
-- name alone came from.
--
-- A country rule challenges a named crawler like anyone, and the link-preview
-- fetchers of the social networks are named crawlers calling from abroad: an
-- operator writing the rule against the world's scrapers could not see that it
-- would stop them, and the first sign was a day of posts without their cards.
-- Split by country, this table lets the country tab say, before the rule is
-- saved, which named crawlers the last day's traffic says it would stop and
-- how many requests that is.
--
-- SQLite cannot widen a PRIMARY KEY in place, so the table is rebuilt.  The
-- rows carry over with country='' (unknown), which the estimate reads as a
-- country the rule does not name.  Written to be safe when the file re-runs
-- after a crash between its statements: OR IGNORE on the copy, IF NOT EXISTS
-- on the create.

-- Drop first: in SQLite an index follows its table through RENAME, so leaving
-- it attached to the old table would collide with the recreate below.
DROP INDEX IF EXISTS idx_crawler_named_hour;

CREATE TABLE IF NOT EXISTS unmask_crawler_named_hourly_v2 (
    bucket_hour INTEGER NOT NULL,                 -- hour bucket (unix epoch seconds / 3600)
    crawler     VARCHAR(48) NOT NULL,             -- individual crawler name (classify.LookupCrawler)
    country     VARCHAR(2) NOT NULL DEFAULT '',   -- ISO 3166-1 alpha-2 of the client address, '' when unknown
    cnt         INTEGER NOT NULL DEFAULT 0,       -- requests passed on the name alone in the hour
    ips         BLOB,                             -- HyperLogLog sketch of their client addresses (internal/hll)
    PRIMARY KEY (bucket_hour, crawler, country)
);

INSERT OR IGNORE INTO unmask_crawler_named_hourly_v2
    (bucket_hour, crawler, country, cnt, ips)
    SELECT bucket_hour, crawler, '', cnt, ips
      FROM unmask_crawler_named_hourly;

DROP TABLE unmask_crawler_named_hourly;
ALTER TABLE unmask_crawler_named_hourly_v2 RENAME TO unmask_crawler_named_hourly;

CREATE INDEX IF NOT EXISTS idx_crawler_named_hour ON unmask_crawler_named_hourly(bucket_hour);
