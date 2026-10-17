-- 0043 AI prompt cache tokens.  See the sqlite counterpart: the part of a
-- call's input the provider served from its prompt cache, and the part it
-- wrote to it, each billed at its own rate.
--
-- IF NOT EXISTS: a database a development build already gave the columns
-- takes this as done.
ALTER TABLE unmask_ai_chat
    ADD COLUMN IF NOT EXISTS cache_read_tokens INT NOT NULL DEFAULT 0
        COMMENT 'input tokens the provider read from its prompt cache (a part of in_tokens)'
        AFTER added_rules,
    ADD COLUMN IF NOT EXISTS cache_write_tokens INT NOT NULL DEFAULT 0
        COMMENT 'input tokens the provider wrote to its prompt cache (a part of in_tokens)'
        AFTER cache_read_tokens;
ALTER TABLE unmask_advisor_run
    ADD COLUMN IF NOT EXISTS cache_read_tokens INT NOT NULL DEFAULT 0
        COMMENT 'as unmask_ai_chat.cache_read_tokens'
        AFTER err,
    ADD COLUMN IF NOT EXISTS cache_write_tokens INT NOT NULL DEFAULT 0
        COMMENT 'as unmask_ai_chat.cache_write_tokens'
        AFTER cache_read_tokens;
