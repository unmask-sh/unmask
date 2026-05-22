-- 0008 traffic_hll: HyperLogLog sketches of client IPs over ALL traffic,
-- written by the nginx-log pipeline (the unmask_minimal access-log feed).
--
-- unmask_cookie_minute holds per-minute request *counts* but not IPs, so the
-- overview could only show non-human traffic as a share of request volume --
-- a figure skewed by a single high-volume bot.  This table adds mergeable
-- per-minute distinct-IP sketches so the overview can show the non-human
-- share by *unique client* instead.
--
-- bucket_min : unix epoch minute (time.Unix()/60), same clock as
--              unmask_cookie_minute.
-- site       : $host of the request (same value as unmask_cookie_minute.site).
-- kind       : ip  -> every request's IP         (= all unique clients)
--              ipc -> IP of fc=1 requests        (= challenged clients)
--              ipp -> IP carrying a pow/captcha   _bv cookie (= passed before)
-- sketch     : 1024-byte HLL register array (precision p=10).
--
-- Written by nginxlog.Reader on each minute flush (read-merge-write so a
-- restart / late datagram does not lose a bucket); merged + estimated on read.
CREATE TABLE IF NOT EXISTS unmask_traffic_hll (
    bucket_min  INTEGER NOT NULL,
    site        VARCHAR(64) NOT NULL,
    kind        VARCHAR(8) NOT NULL,
    sketch      BLOB NOT NULL,
    PRIMARY KEY (bucket_min, site, kind)
);
