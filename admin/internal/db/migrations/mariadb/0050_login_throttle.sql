-- 0050 login_throttle: the credential endpoints' per-address counters.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_login_throttle (
    k            VARCHAR(80) NOT NULL COMMENT 'counter key: axis prefix (l| login failures, f| forgot-password requests) + address (an IPv6 address by its /64)',
    cnt          INT NOT NULL DEFAULT 0 COMMENT 'events counted in the current window',
    window_start BIGINT NOT NULL DEFAULT 0 COMMENT 'unix time (UTC) the current window opened',
    locked_until BIGINT NOT NULL DEFAULT 0 COMMENT 'unix time (UTC) the lock holds until; 0 = not locked',
    updated_at   BIGINT NOT NULL DEFAULT 0 COMMENT 'unix time (UTC) of the last change (the prune reads it)',
    PRIMARY KEY (k),
    KEY idx_login_throttle_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-address counters of the admin login lockout and the forgot-password cap, shared by every node and kept over a restart';
