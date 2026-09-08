-- 0031 maintenance state.  See the SQLite copy for the reasoning.
CREATE TABLE IF NOT EXISTS unmask_maint_state (
    name VARCHAR(64) NOT NULL COMMENT 'task name (events_prune)',
    value TEXT NOT NULL COMMENT 'JSON: the task''s last-run record',
    updated_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) of the last write',
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Last-run record per timed maintenance task (events prune), read by doctor and the retention tab';
