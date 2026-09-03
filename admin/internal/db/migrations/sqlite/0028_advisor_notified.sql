-- 0028 advisor notified list: remembers which advisor candidates have already
-- been carried in a scheduled digest, so the next digest reports what is NEW
-- rather than repeating yesterday's list every night until the operator acts.
--
-- One row per target that has been announced once.  Kept small by the same
-- forces that keep the candidate list small (a handful of loud addresses per
-- window), and pruned by age in the scheduler rather than by a retention job:
-- an address that stops being a candidate for long enough should be able to
-- earn a fresh mention if it comes back.
CREATE TABLE IF NOT EXISTS unmask_advisor_notified (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,      -- advisor candidate type: 'ip' | 'ja4'
    target TEXT NOT NULL,           -- the announced address / fingerprint
    notified_at INTEGER NOT NULL,   -- unix seconds (UTC) of the digest that carried it
    UNIQUE(target_type, target)
);
