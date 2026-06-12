-- Roaming silent-rebind cap: bounds how many times / how fast one solved
-- challenge (keyed by the random lineage id in its _bvj cookie) is re-bound to
-- a new client IP.  See cookies._bvj and settings.RebindConfig.
CREATE TABLE IF NOT EXISTS unmask_rebind_lineage (
    lineage      VARCHAR(32)  NOT NULL PRIMARY KEY,
    host         VARCHAR(255) NOT NULL DEFAULT '',
    count        INT          NOT NULL DEFAULT 0,
    window_start BIGINT       NOT NULL DEFAULT 0,
    window_count INT          NOT NULL DEFAULT 0,
    updated_at   BIGINT       NOT NULL DEFAULT 0,
    INDEX idx_rebind_lineage_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
