-- 0036 AI chat.  See the sqlite counterpart: one row per question an
-- operator asked the model from the admin's "ask" page.
CREATE TABLE IF NOT EXISTS unmask_ai_chat (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL COMMENT 'unmask_user.id of the account that asked',
    asked_at BIGINT NOT NULL COMMENT 'unix seconds (UTC) the answer landed (or failed)',
    question TEXT NOT NULL COMMENT 'the operator''s question, as typed',
    answer MEDIUMTEXT NOT NULL COMMENT 'the model''s answer; empty when the turn failed',
    tools TEXT NOT NULL COMMENT 'JSON array of {name, args, ms, err}: the read-only tools the answer drew on',
    model VARCHAR(128) NOT NULL DEFAULT '' COMMENT 'model id the turn used',
    in_tokens INT NOT NULL DEFAULT 0 COMMENT 'input tokens the provider reported, all rounds (0 = not reported)',
    out_tokens INT NOT NULL DEFAULT 0 COMMENT 'output tokens the provider reported, all rounds',
    err TEXT NOT NULL COMMENT 'non-empty when the turn failed (the provider''s reason)',
    INDEX idx_unmask_ai_chat_user (user_id, asked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='questions an operator asked the model from the admin, with the answers (pruned past 90 days)';
