-- Roaming silent-rebind cap: bounds how many times / how fast one solved
-- challenge (keyed by the random lineage id in its _bvj cookie) is re-bound to
-- a new client IP.  See cookies._bvj and settings.RebindConfig.
CREATE TABLE IF NOT EXISTS unmask_rebind_lineage (
    lineage      TEXT    NOT NULL PRIMARY KEY,  -- random lineage id from the _bvj cookie
    host         TEXT    NOT NULL DEFAULT '',   -- host the lineage is bound to
    count        INTEGER NOT NULL DEFAULT 0,    -- total silent rebinds for this lineage
    window_start INTEGER NOT NULL DEFAULT 0,    -- start of the current rate window (unix seconds)
    window_count INTEGER NOT NULL DEFAULT 0,    -- rebinds within the current window
    updated_at   INTEGER NOT NULL DEFAULT 0     -- last update (unix seconds)
);
CREATE INDEX IF NOT EXISTS idx_rebind_lineage_updated ON unmask_rebind_lineage (updated_at);
