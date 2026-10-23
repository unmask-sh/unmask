-- 0046 user session generation.  See the sqlite counterpart: a number a
-- session cookie is issued under and refused without, advanced by a password
-- change and by a suspension so those end every session the account holds.
--
-- IF NOT EXISTS: a database a development build already gave the column
-- takes this as done.
ALTER TABLE unmask_user
    ADD COLUMN IF NOT EXISTS session_gen BIGINT NOT NULL DEFAULT 0
        COMMENT 'session generation: a session cookie is refused unless it carries this value; advanced by a password change and by a suspension'
        AFTER password_locked;
