-- 0041 user password lock.  See the sqlite counterpart: an account the
-- administrator keeps from changing its own password (a viewer login shared
-- by a team); the users page still sets it.
--
-- IF NOT EXISTS: a database a development build already gave the column
-- takes this as done.
ALTER TABLE unmask_user
    ADD COLUMN IF NOT EXISTS password_locked TINYINT NOT NULL DEFAULT 0
        COMMENT '1 = the account cannot change its own password (profile page, forgot-password link); an administrator sets it from the users page'
        AFTER ui_lang;
