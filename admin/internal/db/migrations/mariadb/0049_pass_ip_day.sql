-- 0049 pass_ip_day: the pass cookies each address presented in a day.
-- See the sqlite counterpart for the rationale.
CREATE TABLE IF NOT EXISTS unmask_pass_ip_day (
    bucket_day  BIGINT NOT NULL COMMENT 'day bucket (unix epoch seconds / 86400, UTC)',
    site        VARCHAR(64) NOT NULL COMMENT 'logical site/vhost',
    ip          VARBINARY(16) NOT NULL COMMENT 'client IP as raw bytes (4 for v4, 16 for v6)',
    cookies     INT NOT NULL DEFAULT 0 COMMENT 'distinct pass cookies (entries) the address presented in the day',
    ja4s        INT NOT NULL DEFAULT 0 COMMENT 'distinct JA4 fingerprints seen with them (up to 256)',
    ja4         VARCHAR(40) NOT NULL DEFAULT '' COMMENT 'the latest JA4 fingerprint seen for the address in the day',
    cnt         INT NOT NULL DEFAULT 0 COMMENT 'requests carrying a pass cookie (every logged line)',
    judged      INT NOT NULL DEFAULT 0 COMMENT 'of cnt, the requests the gate judged (what a cap counts)',
    peak_hour   INT NOT NULL DEFAULT 0 COMMENT 'the most judged requests one cookie made in a single hour of the day',
    ua          VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'latest User-Agent seen for the address in the day (truncated to 255)',
    last_seen   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'latest request time (UTC)',
    PRIMARY KEY (bucket_day, site, ip),
    KEY idx_pass_ip_day (bucket_day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-day per-address count of distinct pass cookies and the busiest hour of one of them (stats page ranking)';
