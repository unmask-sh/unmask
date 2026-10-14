-- 0038 event date cover index.  SQLite only: see the sqlite counterpart.  The
-- reads it speeds up were measured on SQLite, whose table lookups from a
-- large file were the cost; MariaDB keeps its date index (idx_date) and reads
-- as it did.  The file keeps the migration number allocated on both drivers;
-- the body is a no-op marker.
SELECT 1 WHERE 0;
