-- 0023 cookie_ip_minute kind.  See the sqlite counterpart for the rationale:
-- a request carrying a valid _bv cookie fires no challenge and so writes no
-- unmask_event row, which makes a scraper riding one PoW-solved cookie
-- invisible to every per-IP view in the dashboard.  This table already held the
-- only record of that traffic and simply discarded everything but kind="captcha".
--
-- MariaDB can widen the PRIMARY KEY in place.  IF NOT EXISTS on the column keeps
-- the file a no-op on a fresh install, where migrate.go has already created the
-- new shape before the numbered migrations run.  Existing rows are all CAPTCHA
-- reuse by construction, which is what the column default backfills them to.
ALTER TABLE unmask_cookie_ip_minute
    ADD COLUMN IF NOT EXISTS kind VARCHAR(16) NOT NULL DEFAULT 'captcha'
        COMMENT 'how the reused cookie was earned (captcha / pow)' AFTER ip,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (bucket_min, site, ip, kind);

-- One kind is read at a time over a window the PK cannot seek by (it leads with
-- bucket_min), so without this the CAPTCHA section scans the PoW rows that
-- outnumber it ~8:1 -- the trap 0022 fixed on unmask_traffic_hll.
CREATE INDEX IF NOT EXISTS idx_cookie_ip_kind_min
    ON unmask_cookie_ip_minute (kind, bucket_min);
