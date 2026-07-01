-- 0008 traffic_hll: HyperLogLog sketches of client IPs over ALL traffic.
-- See the sqlite counterpart for the rationale and the kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_traffic_hll (
    bucket_min  BIGINT NOT NULL COMMENT 'unix epoch minute (time.Unix()/60), same clock as unmask_cookie_minute',
    site        VARCHAR(64) NOT NULL COMMENT 'request $host',
    kind        VARCHAR(8) NOT NULL COMMENT 'ip (all clients) / ipc (challenged) / ipp (carried a pow/captcha _bv)',
    sketch      BLOB NOT NULL COMMENT '1024-byte HLL register array (precision p=10)',
    PRIMARY KEY (bucket_min, site, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Per-minute distinct-client-IP HLL sketches over all traffic (nginx-log pipeline)';
