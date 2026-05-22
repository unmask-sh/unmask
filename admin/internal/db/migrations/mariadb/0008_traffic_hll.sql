-- 0008 traffic_hll: HyperLogLog sketches of client IPs over ALL traffic.
-- See the sqlite counterpart for the rationale and the kind catalogue.
CREATE TABLE IF NOT EXISTS unmask_traffic_hll (
    bucket_min  BIGINT NOT NULL,
    site        VARCHAR(64) NOT NULL,
    kind        VARCHAR(8) NOT NULL,
    sketch      BLOB NOT NULL,
    PRIMARY KEY (bucket_min, site, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
