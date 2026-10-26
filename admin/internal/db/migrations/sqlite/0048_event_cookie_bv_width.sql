-- 0048 event cookie_bv width.  MariaDB only: see the mariadb counterpart.
-- SQLite does not enforce a VARCHAR's declared width, so the column holds
-- the cookie as the beacon reads it already; the base schema now declares
-- 1024, which is informational here.  The file keeps the migration number
-- allocated on both drivers; the body is a no-op marker.
SELECT 1 WHERE 0;
