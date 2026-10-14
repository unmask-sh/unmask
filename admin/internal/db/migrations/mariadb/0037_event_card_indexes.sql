-- 0037 event card indexes.  SQLite only: see the sqlite counterpart.  They
-- are partial indexes (a WHERE on the index), which MariaDB does not have, and
-- an index over every event for the few each card reads would make every write
-- pay for it.  MariaDB keeps the cards' queries as they were.  The file keeps
-- the migration number allocated on both drivers; the body is a no-op marker.
SELECT 1 WHERE 0;
