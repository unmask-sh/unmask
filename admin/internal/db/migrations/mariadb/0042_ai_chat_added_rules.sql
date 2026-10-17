-- 0042 AI chat added rules.  See the sqlite counterpart: the custom rules an
-- operator added from an answer's "make this rule" buttons, so the history
-- shows a button as made while its rule is on the list.
--
-- IF NOT EXISTS: a database a development build already gave the column
-- takes this as done.
ALTER TABLE unmask_ai_chat
    ADD COLUMN IF NOT EXISTS added_rules TEXT NOT NULL
        COMMENT 'JSON object: a rule button''s path in the answer (the create_path propose_custom_rule gave) -> the id of the custom rule added from it; empty = none'
        AFTER err;
