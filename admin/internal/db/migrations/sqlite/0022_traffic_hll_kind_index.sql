-- 0022 traffic_hll kind index: speed up DailyUniqueIPs.
--
-- DailyUniqueIPs reads WHERE kind='ip' AND bucket_min>=cutoff over a 30-day
-- window.  The PRIMARY KEY (bucket_min, site, kind) leads with bucket_min, so
-- the planner cannot seek by kind -- it scans every kind in the range
-- (ip/ipc/ipp, ~130k rows / ~70 MB of sketches on a busy install) and filters.
-- On a write-busy SQLite file the scan contends with the nginx-log pipeline's
-- writes and can exceed the dashboard's per-card deadline, surfacing as a
-- repeated "DailyUniqueIPs query errored" card.  Indexing (kind, bucket_min)
-- lets the read touch only the matching kind (measured 4.8s -> ~0.2s on a
-- 65k-row 'ip' set).  IF NOT EXISTS so installs that already created it live
-- (hotfix) are a no-op.
CREATE INDEX IF NOT EXISTS idx_unmask_traffic_hll_kind_bucket
    ON unmask_traffic_hll (kind, bucket_min);
