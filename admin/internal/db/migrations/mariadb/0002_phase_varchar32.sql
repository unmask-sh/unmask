-- 0002 phase column: VARCHAR(16) → VARCHAR(32).
--
-- New phase names (e.g. bv_pow_then_captcha = 19 chars) overflow the v1
-- baseline width.  MariaDB enforces VARCHAR length, so existing v1 DBs need
-- this ALTER before the new beacon payloads start arriving.
ALTER TABLE unmask_event MODIFY phase VARCHAR(32) NOT NULL;
