-- 0052 let_through: what the site answered without a challenge, and why.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_let_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'hour bucket (unix epoch seconds / 3600, UTC)',
    site        VARCHAR(64) NOT NULL COMMENT 'logical site/vhost',
    reason      VARCHAR(16) NOT NULL COMMENT 'the ground the request passed on (the access log why=): cookie, ip, path, name, preview, global, signed, watch, nogate, down, none',
    detail      VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'what the reason matched: cookie kind, bypass range or path row, crawler; empty when none',
    cnt         BIGINT NOT NULL DEFAULT 0 COMMENT 'requests',
    ips         BLOB COMMENT 'HyperLogLog sketch of the client addresses',
    PRIMARY KEY (bucket_hour, site, reason, detail)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour count of requests the site answered without a challenge, by the ground they passed on';

CREATE TABLE IF NOT EXISTS unmask_let_ip_hourly (
    bucket_hour BIGINT NOT NULL COMMENT 'hour bucket (unix epoch seconds / 3600, UTC)',
    site        VARCHAR(64) NOT NULL COMMENT 'logical site/vhost',
    reason      VARCHAR(16) NOT NULL COMMENT 'the ground the request passed on (never cookie: a pass is counted, not listed)',
    detail      VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'what the reason matched: bypass range or path row, crawler; empty when none',
    ip          VARBINARY(16) NOT NULL COMMENT 'client IP as raw bytes (4 for v4, 16 for v6)',
    cnt         INT NOT NULL DEFAULT 0 COMMENT 'requests from the address in the hour, on this ground',
    first_seen  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'earliest request time (UTC)',
    last_seen   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'latest request time (UTC)',
    ja4         VARCHAR(40) NOT NULL DEFAULT '' COMMENT 'the latest JA4 fingerprint seen for the address',
    ua          VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'latest User-Agent seen for the address (truncated to 255)',
    path        VARCHAR(200) NOT NULL DEFAULT '' COMMENT 'latest path the address asked for (up to the query, truncated to 200)',
    PRIMARY KEY (bucket_hour, site, reason, detail, ip),
    KEY idx_let_ip_hourly_ip (ip, bucket_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-hour busiest addresses behind the requests the site answered without a challenge, by ground (BAN > Let through)';
