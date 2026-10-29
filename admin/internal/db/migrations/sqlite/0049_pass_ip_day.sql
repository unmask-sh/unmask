-- 0049 pass_ip_day: the pass cookies each address presented in a day.
--
-- A request carrying a valid pass cookie fires no challenge and writes no
-- event; the access log is the only record of it.  unmask_cookie_ip_minute
-- counts those REQUESTS per address.  This table counts the COOKIES: how many
-- distinct passes an address presented in a day, and how busy a single one of
-- them got in an hour.  A pass is bound to the address and the host, so one
-- cookie is one browser on one network: an address with many is many people
-- (an office proxy, a carrier NAT) or one client solving the challenge over
-- and over, and one that rides a single pass hard shows in the hourly peak.
-- Those two figures are what a per-cookie limit would be read against, and
-- what the reuse cap, which counts per address, cannot tell apart.
--
-- The daemon keeps the day's set of cookies in memory and writes its size:
-- cookies and ja4s are levels (the stored row keeps the larger), cnt and
-- judged accumulate, peak_hour keeps the larger.  A restart forgets the set,
-- so a day's count can fall short of the truth, never run past it.  Days and
-- hours are UTC.
--
-- Pruned at 15 days (PruneHourly), like the PoW rows of the reuse table: a
-- pass lives 7 days by default, so a longer window sums cookie generations.
--
-- bucket_day : day bucket (unix epoch seconds / 86400, UTC).
-- site       : logical site/vhost.
-- ip         : client IP as raw bytes (4 for v4, 16 for v6).
-- cookies    : distinct pass cookies (entries) the address presented in the day.
-- ja4s       : distinct JA4 fingerprints seen with them (up to 256).
-- ja4        : the latest JA4 fingerprint seen for the address in the day.
-- cnt        : requests carrying a pass cookie (every logged line).
-- judged     : of cnt, the requests the gate judged (what a cap counts).
-- peak_hour  : the most judged requests one cookie made in a single hour of the day.
-- ua         : latest User-Agent seen for the address in the day (truncated to 255).
-- last_seen  : latest request time (UTC).
CREATE TABLE IF NOT EXISTS unmask_pass_ip_day (
    bucket_day  INTEGER NOT NULL,                            -- day bucket (unix epoch seconds / 86400, UTC)
    site        VARCHAR(64) NOT NULL,                        -- logical site/vhost
    ip          BLOB NOT NULL,                               -- client IP as raw bytes (4 for v4, 16 for v6)
    cookies     INTEGER NOT NULL DEFAULT 0,                  -- distinct pass cookies (entries) the address presented in the day
    ja4s        INTEGER NOT NULL DEFAULT 0,                  -- distinct JA4 fingerprints seen with them (up to 256)
    ja4         VARCHAR(64) NOT NULL DEFAULT '',             -- the latest JA4 fingerprint seen for the address in the day
    cnt         INTEGER NOT NULL DEFAULT 0,                  -- requests carrying a pass cookie (every logged line)
    judged      INTEGER NOT NULL DEFAULT 0,                  -- of cnt, the requests the gate judged (what a cap counts)
    peak_hour   INTEGER NOT NULL DEFAULT 0,                  -- the most judged requests one cookie made in a single hour of the day
    ua          VARCHAR(255) NOT NULL DEFAULT '',            -- latest User-Agent seen for the address in the day (truncated to 255)
    last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- latest request time (UTC)
    PRIMARY KEY (bucket_day, site, ip)
);
CREATE INDEX IF NOT EXISTS idx_pass_ip_day ON unmask_pass_ip_day(bucket_day);
