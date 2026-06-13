-- Roaming silent-rebind cap: bounds how many times / how fast one solved
-- challenge (keyed by the random lineage id in its _bvj cookie) is re-bound to
-- a new client IP.  See cookies._bvj and settings.RebindConfig.
CREATE TABLE IF NOT EXISTS unmask_rebind_lineage (
    lineage      VARCHAR(32)  NOT NULL PRIMARY KEY COMMENT 'random lineage id from the _bvj cookie',
    host         VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'host the lineage is bound to',
    count        INT          NOT NULL DEFAULT 0 COMMENT 'total silent rebinds for this lineage',
    window_start BIGINT       NOT NULL DEFAULT 0 COMMENT 'start of the current rate window (unix seconds)',
    window_count INT          NOT NULL DEFAULT 0 COMMENT 'rebinds within the current window',
    updated_at   BIGINT       NOT NULL DEFAULT 0 COMMENT 'last update (unix seconds)',
    INDEX idx_rebind_lineage_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Roaming silent-rebind rate cap, keyed by _bvj lineage id';
