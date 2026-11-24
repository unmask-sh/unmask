-- 0053 let_through address index: let BAN > Let through fold a ground's
-- addresses without a sort.
--
-- Not deferrable: the table holds eight days at most (PruneHourly), so the
-- build is short wherever it runs.
--
-- The page lists, per ground, the busiest addresses of the window:
--   WHERE reason = ? AND bucket_hour BETWEEN ? AND ?
--   GROUP BY site, ip, detail ORDER BY SUM(cnt) DESC LIMIT ?
-- The PRIMARY KEY (bucket_hour, site, reason, detail, ip) leads with the
-- hour, so each ground's read walked every ground's rows of the window and
-- sorted its own into groups.  A row is kept per site, hour, ground and
-- address, so on an install with many sites a week is a great many rows, and
-- the page read them once per ground.
-- Leading with the ground and then the group's columns, in the GROUP BY's
-- order, hands the rows over already grouped, and carrying the hour, the
-- count and the two times makes the index all the read needs.  IF NOT EXISTS
-- so a database that already has it passes through without work.
CREATE INDEX IF NOT EXISTS idx_let_ip_hourly_reason
    ON unmask_let_ip_hourly (reason, site, ip, detail, bucket_hour, cnt, first_seen, last_seen);
