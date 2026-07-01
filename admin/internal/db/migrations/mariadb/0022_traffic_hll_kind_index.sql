-- 0022 traffic_hll kind index.  See the sqlite counterpart for the rationale:
-- DailyUniqueIPs filters WHERE kind='ip' AND bucket_min>=cutoff, but the PK
-- (bucket_min, site, kind) can't seek by kind, so a 30-day read scans every
-- kind and can exceed the dashboard's per-card deadline.  Indexing
-- (kind, bucket_min) confines the read to the matching kind.
CREATE INDEX IF NOT EXISTS idx_unmask_traffic_hll_kind_bucket
    ON unmask_traffic_hll (kind, bucket_min);
