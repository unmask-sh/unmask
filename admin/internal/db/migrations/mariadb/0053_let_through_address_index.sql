-- 0053 let_through address index (see the sqlite file for why, and why it is
-- not deferrable: the table holds eight days at most).
--
-- The page groups a ground's rows of the window by (site, ip, detail), and
-- the PRIMARY KEY (bucket_hour, site, reason, detail, ip) leads with the
-- hour.  (reason, site, ip, detail, bucket_hour, cnt, first_seen, last_seen)
-- confines the read to the ground, in the GROUP BY's order, and covers it.
CREATE INDEX IF NOT EXISTS idx_let_ip_hourly_reason
    ON unmask_let_ip_hourly (reason, site, ip, detail, bucket_hour, cnt, first_seen, last_seen);
