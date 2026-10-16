-- 0040 notices: the alerts the daemon sends by webhook and mail (a ban, a
-- challenge burst, the over-block breaker tripping or clearing, the advisor's
-- digest), kept for the admin's own notification list -- the bell in the top
-- bar -- whatever the external channels are set to: it is the one channel
-- every install has.  Bans fold into one row per hour (group_key), so a
-- honeypot that trips all day is a row an hour, not hundreds.  The row holds
-- the event's figures, not a text: the page writes the line in the reader's
-- language.  user_id names the one account a row is for; NULL is every
-- administrator.  Pruned with the audit log (audit_retention_days).
CREATE TABLE IF NOT EXISTS unmask_notice (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,         -- unix seconds (UTC) of the event, the first one when the row folds several
    updated_at INTEGER NOT NULL,         -- unix seconds of the last event folded into the row (= created_at for a lone event)
    kind TEXT NOT NULL,                  -- ban_created / challenge_burst / over_block / advisor_digest (the webhook's event name)
    severity TEXT NOT NULL,              -- info / warn / crit: how the row is marked
    user_id INTEGER,                     -- unmask_user.id of the one account the row is for; NULL = every administrator
    site TEXT NOT NULL DEFAULT '',       -- notifications.site_label as it read when the event happened ('' when none)
    group_key TEXT NOT NULL DEFAULT '',  -- rows that fold into one share it (bans: kind + the hour); '' = never folded
    events INTEGER NOT NULL DEFAULT 1,   -- how many events the row stands for
    detail TEXT NOT NULL                 -- JSON: the event's fields as the webhook carries them, less event / site / ts (columns here)
);
CREATE INDEX IF NOT EXISTS idx_unmask_notice_group ON unmask_notice (group_key);

-- How far each account has read: the id of the newest row it had on screen
-- when it last opened the list.  Unread = rows above it.
CREATE TABLE IF NOT EXISTS unmask_notice_seen (
    user_id INTEGER PRIMARY KEY,         -- unmask_user.id
    seen_id INTEGER NOT NULL,            -- unmask_notice.id of the newest row the account had opened the list to
    seen_at INTEGER NOT NULL             -- unix seconds the account last opened the list
);
