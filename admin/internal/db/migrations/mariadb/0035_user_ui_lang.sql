-- 0035 user ui lang.  See the sqlite counterpart: the over-block alert is
-- written in the language each account last saw the admin in, recorded as it
-- uses the admin.
--
-- IF NOT EXISTS: a database a development build already gave the column
-- takes this as done.
ALTER TABLE unmask_user
    ADD COLUMN IF NOT EXISTS ui_lang VARCHAR(8) NOT NULL DEFAULT ''
        COMMENT 'language the account last saw the admin in (empty before its first visit); the over-block alert is written in it'
        AFTER last_login;
