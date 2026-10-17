-- 0043 AI prompt cache tokens: the part of a call's input the provider served
-- from its prompt cache, and the part it wrote to it, on the ask page's turns
-- and the advisor's runs.
--
-- The ask page sends the same system prompt and tools with every round of a
-- question and, from 2026-10-18, marks them for Anthropic's prompt cache;
-- OpenAI caches a repeated prefix on its own.  A token read back from the
-- cache is billed at a tenth of the input rate (Anthropic writes one at
-- 1.25), so the page's estimates need the split: in_tokens stays the whole
-- prompt, these are the parts of it at the other rates.
ALTER TABLE unmask_ai_chat ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0; -- input tokens the provider read from its prompt cache (a part of in_tokens)
ALTER TABLE unmask_ai_chat ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0; -- input tokens the provider wrote to its prompt cache (a part of in_tokens)
ALTER TABLE unmask_advisor_run ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0; -- as unmask_ai_chat.cache_read_tokens
ALTER TABLE unmask_advisor_run ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0; -- as unmask_ai_chat.cache_write_tokens
