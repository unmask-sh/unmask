-- Switch unmask_crawler_minute.category from the legacy 5-bucket scheme
-- (search / training / agent / scraper / collector) to the 11-tag scheme
-- the rest of the dashboard now uses (= classify.CrawlerTagOrder).  See
-- the sqlite counterpart for the reasoning.
UPDATE unmask_crawler_minute SET category = 'search-engine' WHERE category = 'search';
UPDATE unmask_crawler_minute SET category = 'ai-training'   WHERE category = 'training';
UPDATE unmask_crawler_minute SET category = 'ai-user'       WHERE category = 'agent';
UPDATE unmask_crawler_minute SET category = 'ai-crawler'    WHERE category = 'scraper';
UPDATE unmask_crawler_minute SET category = 'archiver'      WHERE category = 'collector';
