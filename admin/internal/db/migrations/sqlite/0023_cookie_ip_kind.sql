-- 0023 cookie_ip_minute kind: split the reuse counter by how the cookie was
-- earned, so PoW-cookie reuse becomes visible alongside CAPTCHA-cookie reuse.
--
-- Why it matters: a request carrying a valid _bv cookie fires no challenge, so
-- it writes no unmask_event row -- and every per-IP view in the dashboard
-- (RankByIP / RateLimitIPs / CaptchaPassTopIPs) reads unmask_event.  A scraper
-- that solved the transparent PoW once and then rides that one cookie for tens
-- of thousands of requests is therefore invisible everywhere.  This table was
-- already the only place that traffic is recorded; it just discarded everything
-- that was not kind="captcha".
--
-- SQLite cannot widen a PRIMARY KEY in place, so the table is rebuilt.  Existing
-- rows are all CAPTCHA reuse by construction (bumpCookieIP recorded nothing
-- else), so they carry over as kind='captcha' and no history is lost.
--
-- Written to be safe when it runs against the post-change base schema too (= a
-- fresh install creates the new shape in migrate.go, then reaches this file):
-- the SELECT names its columns and supplies the literal kind, and the table is
-- empty there, so the rebuild is a no-op rather than a kind-flattening rewrite.

-- Drop first: in SQLite an index follows its table through RENAME, so leaving
-- it attached to the old table would collide with the recreate below.
DROP INDEX IF EXISTS idx_cookie_ip_minute_site_min;

CREATE TABLE IF NOT EXISTS unmask_cookie_ip_minute_v2 (
    bucket_min  INTEGER NOT NULL,                            -- minute bucket (unix epoch seconds / 60)
    site        VARCHAR(64) NOT NULL,                        -- logical site/vhost
    ip          BLOB NOT NULL,                               -- client IP as raw bytes (4 for v4, 16 for v6)
    kind        VARCHAR(16) NOT NULL DEFAULT 'captcha',      -- how the reused cookie was earned (captcha / pow)
    ja4         VARCHAR(40) NOT NULL DEFAULT '',             -- latest JA4 fingerprint seen for this IP in the bucket
    ua          VARCHAR(255) NOT NULL DEFAULT '',            -- latest User-Agent seen for this IP in the bucket (truncated to 255)
    cnt         INTEGER NOT NULL DEFAULT 0,                  -- reuse request count for this (minute, site, ip, kind)
    last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- latest request time (UTC)
    PRIMARY KEY (bucket_min, site, ip, kind)
);

-- OR IGNORE so a crash between these statements (schema_migrations is only
-- written on success, so the whole file re-runs) cannot fail on duplicates.
INSERT OR IGNORE INTO unmask_cookie_ip_minute_v2
    (bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
    SELECT bucket_min, site, ip, 'captcha', ja4, ua, cnt, last_seen
      FROM unmask_cookie_ip_minute;

DROP TABLE unmask_cookie_ip_minute;
ALTER TABLE unmask_cookie_ip_minute_v2 RENAME TO unmask_cookie_ip_minute;

CREATE INDEX IF NOT EXISTS idx_cookie_ip_minute_site_min
    ON unmask_cookie_ip_minute(site, bucket_min);
-- The card reads one kind at a time over a window the PK cannot seek by (it
-- leads with bucket_min).  Without this, rendering the CAPTCHA section scans
-- the PoW rows -- which outnumber it ~8:1 -- and vice versa: the same trap 0022
-- fixed on unmask_traffic_hll, where an unindexed kind filter pushed a card
-- past its deadline.
CREATE INDEX IF NOT EXISTS idx_cookie_ip_minute_kind_min
    ON unmask_cookie_ip_minute(kind, bucket_min);
