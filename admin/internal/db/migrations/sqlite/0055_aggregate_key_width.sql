-- 0055 aggregate key width.  MariaDB only: see the mariadb counterpart.
-- SQLite does not enforce a VARCHAR's declared width, so the two rollup
-- tables hold a key of any length already (the fold cuts one to
-- dashboard.bucketKeyWidth on both drivers).  The file keeps the migration
-- number allocated on both drivers; the body is a no-op marker.
SELECT 1 WHERE 0;
