-- 0029 advisor last result: the model's last answer for one window, kept
-- across restarts.  The page shows "the model's opinion from <when>" and the
-- reviews / nominations it produced; before this table that lived in process
-- memory only, so a restart (an upgrade, a deploy) silently turned a paid
-- answer into "the model has not been asked about this window yet".
--
-- One row per result key (window | provider | model | endpoint | language),
-- upserted on every run.  A handful of rows per install; never pruned, the
-- next run overwrites.
CREATE TABLE IF NOT EXISTS unmask_advisor_result (
    key_hash TEXT PRIMARY KEY,           -- sha1 hex of result_key (the key can be long: it carries the endpoint)
    result_key TEXT NOT NULL,            -- window|provider|model|endpoint|lang, readable
    ran_at INTEGER NOT NULL,             -- unix seconds (UTC) the run finished
    model TEXT NOT NULL,                 -- model id the answer came from
    payload TEXT NOT NULL,               -- JSON: reviews, nominated rows, reverse DNS
    err TEXT NOT NULL DEFAULT ''         -- non-empty when the run failed (payload then empty)
);
