-- 0027 advisor dismiss list: remembers which advisor-suggested ban candidates
-- the operator rejected, so /admin/advisor/ stops re-proposing them.  One row
-- per deliberate operator click, so the table stays tiny and needs no
-- retention window.  The unique pair makes a repeat dismiss an upsert, not a
-- duplicate.
CREATE TABLE IF NOT EXISTS unmask_advisor_dismiss (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,              -- advisor candidate type: 'ip' | 'ja4'
    target TEXT NOT NULL,                   -- the dismissed address / fingerprint
    dismissed_by TEXT NOT NULL DEFAULT '',  -- admin username that clicked dismiss
    dismissed_at INTEGER NOT NULL,          -- unix seconds (UTC)
    UNIQUE(target_type, target)
);
