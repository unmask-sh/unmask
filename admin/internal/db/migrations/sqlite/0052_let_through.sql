-- 0052 let_through: what the site answered without a challenge, and why.
--
-- A request that is let through fires no challenge and writes no event; the
-- access log is the only record of it, and it said how many (the cookie and
-- crawler buckets) and never who.  These two tables keep, per hour and site,
-- the requests each ground for passing let through, and -- for every ground
-- but the pass cookie -- the addresses behind them, so the admin can list who
-- got pages without the check and ban from the list.
--
-- reason is the configuration's (the access log's why=): cookie, ip (a
-- bypass address), path (a bypass path), name (a crawler by its name alone),
-- preview (a link-preview fetcher by name and network), global (the Global
-- axis says pass), signed (Web Bot Auth / Privacy Pass), watch (monitor mode),
-- nogate (a location without protect.inc), down (the daemon did not answer),
-- none (no ground the configuration can name: a fault).  detail is the
-- daemon's: the cookie's kind, the bypass range or path row, the crawler.
--
-- unmask_let_hourly counts every request of the bucket and keeps a sketch of
-- its addresses.  unmask_let_ip_hourly keeps at most 100 addresses per bucket,
-- the busiest; the row of an address pushed out is deleted.  The daemon
-- writes deltas at every flush.  Hours are UTC.  Pruned with the event log
-- (PruneHourly).
--
-- bucket_hour : hour bucket (unix epoch seconds / 3600, UTC).
-- site        : logical site/vhost.
-- reason      : the ground the request passed on (the access log's why=).
-- detail      : what the reason matched: cookie kind, bypass range or path row, crawler; '' when none.
-- cnt         : requests.
-- ips         : HyperLogLog sketch of the client addresses.
CREATE TABLE IF NOT EXISTS unmask_let_hourly (
    bucket_hour INTEGER NOT NULL,                            -- hour bucket (unix epoch seconds / 3600, UTC)
    site        VARCHAR(64) NOT NULL,                        -- logical site/vhost
    reason      VARCHAR(16) NOT NULL,                        -- the ground the request passed on (the access log's why=)
    detail      VARCHAR(64) NOT NULL DEFAULT '',             -- what the reason matched: cookie kind, bypass range or path row, crawler
    cnt         INTEGER NOT NULL DEFAULT 0,                  -- requests
    ips         BLOB,                                        -- HyperLogLog sketch of the client addresses
    PRIMARY KEY (bucket_hour, site, reason, detail)
);

-- ip          : client IP as raw bytes (4 for v4, 16 for v6).
-- cnt         : requests from the address in the hour, on this ground.
-- first_seen  : earliest request time (UTC).
-- last_seen   : latest request time (UTC).
-- ja4         : the latest JA4 fingerprint seen for the address.
-- ua          : latest User-Agent seen for the address (truncated to 255).
-- path        : latest path the address asked for (up to the query, truncated to 200).
CREATE TABLE IF NOT EXISTS unmask_let_ip_hourly (
    bucket_hour INTEGER NOT NULL,                            -- hour bucket (unix epoch seconds / 3600, UTC)
    site        VARCHAR(64) NOT NULL,                        -- logical site/vhost
    reason      VARCHAR(16) NOT NULL,                        -- the ground the request passed on
    detail      VARCHAR(64) NOT NULL DEFAULT '',             -- what the reason matched
    ip          BLOB NOT NULL,                               -- client IP as raw bytes (4 for v4, 16 for v6)
    cnt         INTEGER NOT NULL DEFAULT 0,                  -- requests from the address in the hour, on this ground
    first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- earliest request time (UTC)
    last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- latest request time (UTC)
    ja4         VARCHAR(40) NOT NULL DEFAULT '',             -- the latest JA4 fingerprint seen for the address
    ua          VARCHAR(255) NOT NULL DEFAULT '',            -- latest User-Agent seen for the address (truncated to 255)
    path        VARCHAR(200) NOT NULL DEFAULT '',            -- latest path the address asked for (truncated to 200)
    PRIMARY KEY (bucket_hour, site, reason, detail, ip)
);
CREATE INDEX IF NOT EXISTS idx_let_ip_hourly_ip ON unmask_let_ip_hourly (ip, bucket_hour);
