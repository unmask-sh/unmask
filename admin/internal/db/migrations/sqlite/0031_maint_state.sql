-- 0031 maintenance state: one row per maintenance task the daemon runs on a
-- timer (the events prune first), holding when it last ran, when it last
-- finished its backlog and what it last reported.  doctor and the retention
-- tab read it: a prune that has not completed for days, or that keeps
-- failing, used to show only in the daemon log -- an operator found a 36 GB
-- file five days after the prune stopped keeping up (2026-09-08).
CREATE TABLE IF NOT EXISTS unmask_maint_state (
    name TEXT PRIMARY KEY,               -- task name (events_prune)
    value TEXT NOT NULL,                 -- JSON: the task's last-run record
    updated_at INTEGER NOT NULL          -- unix seconds (UTC) of the last write
);
