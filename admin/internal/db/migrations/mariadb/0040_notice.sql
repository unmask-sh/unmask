-- 0040 notices.  See the sqlite counterpart: the alerts the daemon sends by
-- webhook and mail, kept for the admin's own notification list (the bell in
-- the top bar); bans fold into one row per hour.
CREATE TABLE IF NOT EXISTS unmask_notice (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) of the event, the first one when the row folds several',
    updated_at BIGINT NOT NULL COMMENT 'unix seconds of the last event folded into the row (= created_at for a lone event)',
    kind VARCHAR(32) NOT NULL COMMENT 'ban_created / challenge_burst / over_block / advisor_digest (the webhook''s event name)',
    severity VARCHAR(8) NOT NULL COMMENT 'info / warn / crit: how the row is marked',
    user_id BIGINT NULL COMMENT 'unmask_user.id of the one account the row is for; NULL = every administrator',
    site VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'notifications.site_label as it read when the event happened (empty when none)',
    group_key VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'rows that fold into one share it (bans: kind + the hour); empty = never folded',
    events INT NOT NULL DEFAULT 1 COMMENT 'how many events the row stands for',
    detail TEXT NOT NULL COMMENT 'JSON: the event''s fields as the webhook carries them, less event / site / ts (columns here)',
    INDEX idx_unmask_notice_group (group_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='the alerts sent by webhook and mail, kept for the admin''s notification list (pruned with the audit log)';

CREATE TABLE IF NOT EXISTS unmask_notice_seen (
    user_id BIGINT NOT NULL PRIMARY KEY COMMENT 'unmask_user.id',
    seen_id BIGINT NOT NULL COMMENT 'unmask_notice.id of the newest row the account had opened the list to',
    seen_at BIGINT NOT NULL COMMENT 'unix seconds the account last opened the list'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='how far each account has read the notification list';
