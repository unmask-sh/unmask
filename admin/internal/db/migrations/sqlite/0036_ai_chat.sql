-- 0036 AI chat: the questions an operator asked the model from the admin's
-- "ask" page, with the answer, so a conversation survives a reload and the
-- next question can carry the last few turns as context.  One row per
-- question; the tools the answer drew on are kept as a short JSON trace so
-- the page can say what data the answer was based on.  Pruned past 90 days
-- on insert; cleared by the operator from the page.
CREATE TABLE IF NOT EXISTS unmask_ai_chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,            -- unmask_user.id of the account that asked
    asked_at INTEGER NOT NULL,           -- unix seconds (UTC) the answer landed (or failed)
    question TEXT NOT NULL,              -- the operator's question, as typed
    answer TEXT NOT NULL DEFAULT '',     -- the model's answer; empty when the turn failed
    tools TEXT NOT NULL DEFAULT '',      -- JSON array of {name, args, ms, err}: the read-only tools the answer drew on
    model TEXT NOT NULL DEFAULT '',      -- model id the turn used
    in_tokens INTEGER NOT NULL DEFAULT 0,  -- input tokens the provider reported, all rounds (0 = not reported)
    out_tokens INTEGER NOT NULL DEFAULT 0, -- output tokens the provider reported, all rounds
    err TEXT NOT NULL DEFAULT ''         -- non-empty when the turn failed (the provider's reason)
);
CREATE INDEX IF NOT EXISTS idx_unmask_ai_chat_user ON unmask_ai_chat (user_id, asked_at);
