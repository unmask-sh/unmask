-- 0030 advisor run log: one row per model call the advisor made (or tried
-- to), so the page can say what the last 30 days cost in tokens.  The last
-- answer per window (0029) is upserted and keeps no history; the operator
-- asked for the token count with the model name, and a monthly total is
-- what makes that number actionable.  No prices: a price table would need
-- maintaining and the provider's invoice is the truth.
--
-- A row per click that reached the model (a click that sent nothing, because
-- no evidence changed, writes none).  Pruned past 400 days on insert.
CREATE TABLE IF NOT EXISTS unmask_advisor_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ran_at INTEGER NOT NULL,             -- unix seconds (UTC) the attempt finished
    result_key TEXT NOT NULL,            -- window|provider|model|endpoint|lang, readable
    model TEXT NOT NULL,                 -- model id the attempt used
    reviewed INTEGER NOT NULL DEFAULT 0, -- candidates sent to the model
    kept INTEGER NOT NULL DEFAULT 0,     -- candidates whose review was carried over (nothing sent)
    in_tokens INTEGER NOT NULL DEFAULT 0,  -- input tokens the provider reported (0 = not reported)
    out_tokens INTEGER NOT NULL DEFAULT 0, -- output tokens the provider reported
    err TEXT NOT NULL DEFAULT ''         -- non-empty when the attempt failed
);
CREATE INDEX IF NOT EXISTS idx_unmask_advisor_run_ran_at ON unmask_advisor_run (ran_at);
