-- Roaming silent-rebind cap: bounds how many times / how fast one solved
-- challenge (keyed by the random lineage id in its _bvj cookie) is re-bound to
-- a new client IP.  See cookies._bvj and settings.RebindConfig.
CREATE TABLE IF NOT EXISTS unmask_rebind_lineage (
    lineage      TEXT    NOT NULL PRIMARY KEY,
    host         TEXT    NOT NULL DEFAULT '',
    count        INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL DEFAULT 0,
    window_count INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rebind_lineage_updated ON unmask_rebind_lineage (updated_at);
