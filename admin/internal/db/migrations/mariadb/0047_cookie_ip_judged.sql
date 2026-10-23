-- 0047 cookie-reuse ranking: the requests the gate judged.  See the sqlite
-- counterpart: the cap counts only what the gate judged, the ranking counted
-- every line of the log.  IF NOT EXISTS: a database a development build
-- already gave the column takes this as done.
ALTER TABLE unmask_cookie_ip_minute
    ADD COLUMN IF NOT EXISTS judged INT NOT NULL DEFAULT 0
        COMMENT 'requests among cnt the gate judged (inside a protected location, not bypassed): what the reuse cap counts'
        AFTER cnt;
