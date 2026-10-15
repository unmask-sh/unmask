-- 0039 community-feed serve index.  SQLite only: see the sqlite counterpart.
-- It is a partial index (a WHERE on the index), which MariaDB does not have,
-- and an index over every serve event for the few the figure reads would make
-- every write pay for it.  MariaDB keeps the figure's query as it was.  The
-- file keeps the migration number allocated on both drivers; the body is a
-- no-op marker.
SELECT 1 WHERE 0;
