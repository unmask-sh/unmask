-- 0054 crawler category width.  MariaDB only: see the mariadb counterpart.
-- SQLite does not enforce a VARCHAR's declared width, so the three crawler
-- tables hold every category already.  The file keeps the migration number
-- allocated on both drivers; the body is a no-op marker.
SELECT 1 WHERE 0;
