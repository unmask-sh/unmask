-- unmask:deferrable table=unmask_aggregate_hourly
--
-- Index-only, so the daemon may leave it for the operator when the table is
-- large (see the package doc of internal/db/migrator.go).
--
-- 0034 aggregate_hourly kind index (see the sqlite file for why).
--
-- The cards read one kind over a window, and the PRIMARY KEY
-- (bucket_hour, bucket_kind, bucket_key) leads with the hour, so a 30-day read
-- walked every kind in the window.  (bucket_kind, bucket_hour, bucket_key,
-- cnt) confines the read to its kind and covers it.
CREATE INDEX IF NOT EXISTS idx_unmask_aggregate_hourly_kind
    ON unmask_aggregate_hourly (bucket_kind, bucket_hour, bucket_key, cnt);
