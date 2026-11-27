-- 0054 crawler category width: room for every category the classifier names.
--
-- The three crawler tables keyed a category in VARCHAR(16), and one of the
-- classifier's twelve (classify.CrawlerTagOrder) is "notification-preview",
-- twenty characters.  Under the default sql_mode (STRICT_TRANS_TABLES) a
-- value longer than its column is an error (1406) that rolls back the
-- transaction it rides in -- the whole minute's flush of the access-log
-- counters.  The rows went back into memory and were tried again a minute
-- later with the same value among them, so one request from that fetcher
-- stopped every per-minute table until the daemon was restarted.
--
-- Not deferrable: a category is one of a fixed set that the readers ask for
-- by name, so the writer cannot cut it to a narrower column, and there is
-- nothing to wait for -- the tables hold thirty-two days at most
-- (PruneHourly), and InnoDB extends a VARCHAR whose length prefix stays one
-- byte (utf8mb4: 16 and 32 characters both do) in place, without copying
-- the table, key columns included.
--
-- SQLite enforces no declared width and has nothing to change (see its
-- counterpart).  TestCrawlerCategoriesFitTheirColumn holds the classifier's
-- set to the width declared here.
ALTER TABLE unmask_crawler_minute
    MODIFY COLUMN category VARCHAR(32) NOT NULL COMMENT 'crawler category (= classify.CrawlerTagOrder)';
ALTER TABLE unmask_crawler_detail_hourly
    MODIFY COLUMN category VARCHAR(32) NOT NULL COMMENT 'crawler category (= classify.CrawlerTagOrder)';
ALTER TABLE unmask_crawler_site_hourly
    MODIFY COLUMN category VARCHAR(32) NOT NULL COMMENT 'crawler category (= classify.CrawlerTagOrder)';
