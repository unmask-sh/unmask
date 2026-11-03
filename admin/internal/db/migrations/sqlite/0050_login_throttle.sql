-- 0050 login_throttle: the credential endpoints' per-address counters.
--
-- The admin's login and forgot-password endpoints lock an address out after
-- repeated failures (handlers/login_throttle.go).  The counters lived in the
-- daemon's memory: a restart forgot them, and behind a load balancer every
-- node counted on its own, so N nodes allowed N times the failures.  This
-- table holds them instead -- one row per counter key, shared by every node
-- on a shared database and kept over a restart.
--
-- k            : counter key: the axis ("l|" login failures, "f|" forgot-password
--                requests) and the address, an IPv6 address by its /64.
-- cnt          : events counted in the current window.
-- window_start : unix time (UTC) the current window opened.
-- locked_until : unix time (UTC) the lock holds until; 0 = not locked.
-- updated_at   : unix time (UTC) of the last change; the prune reads it.
--
-- Pruned hourly (dashboard.PruneHourly): a row whose lock has run out and
-- whose last event is older than the longest window is gone.
CREATE TABLE IF NOT EXISTS unmask_login_throttle (
    k            VARCHAR(80) NOT NULL,       -- counter key: axis prefix + address (an IPv6 address by its /64)
    cnt          INTEGER NOT NULL DEFAULT 0, -- events counted in the current window
    window_start INTEGER NOT NULL DEFAULT 0, -- unix time (UTC) the current window opened
    locked_until INTEGER NOT NULL DEFAULT 0, -- unix time (UTC) the lock holds until; 0 = not locked
    updated_at   INTEGER NOT NULL DEFAULT 0, -- unix time (UTC) of the last change (the prune reads it)
    PRIMARY KEY (k)
);
CREATE INDEX IF NOT EXISTS idx_login_throttle_updated ON unmask_login_throttle(updated_at);
