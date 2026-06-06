-- Switch unmask_crawler_minute.category from the legacy 5-bucket scheme
-- (search / training / agent / scraper / collector) to the 11-tag scheme
-- the rest of the dashboard now uses (= classify.CrawlerTagOrder).
--
-- This is a one-way rename — pre-GA we don't carry compatibility shims
-- (= feedback: no_compat_until_ga).  Rows whose source tag is unknowable
-- collapse onto the closest 11-tag neighbour: collector → archiver, since
-- archiver was the largest contributor to the old collector bucket.
--
-- The aggregation goroutine will already be writing the new tags on every
-- new minute boundary; this just retro-fits old rows so a UNION of the two
-- worlds doesn't show the chart split across "search" + "search-engine"
-- twins.
UPDATE unmask_crawler_minute SET category = 'search-engine' WHERE category = 'search';
UPDATE unmask_crawler_minute SET category = 'ai-training'   WHERE category = 'training';
UPDATE unmask_crawler_minute SET category = 'ai-user'       WHERE category = 'agent';
UPDATE unmask_crawler_minute SET category = 'ai-crawler'    WHERE category = 'scraper';
UPDATE unmask_crawler_minute SET category = 'archiver'      WHERE category = 'collector';
