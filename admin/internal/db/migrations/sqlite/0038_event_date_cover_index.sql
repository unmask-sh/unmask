-- unmask:deferrable table=unmask_event
--
-- Index-only, so the daemon may leave it for the operator when the table is
-- large (see the package doc of internal/db/migrator.go).
--
-- 0038 event date cover index: the event table's date index carries the
-- columns that reads of a time window take, so they read the index alone.
--
-- The date index held the time only.  A read of a window -- the bot hunt's
-- address ranking, the funnel and verdict cards for a window under a day or
-- before the hourly rollup is ready, the rate-limit funnel's rollup and its
-- live hours -- found its rows there and then read each one from the table
-- for its address, phase or verdict.  On a database larger than memory those
-- rows lie far apart, a seek each: on a test database a day's funnel scan
-- took 104 s cold, and with this index 13 s; a day's address ranking 100 s,
-- now 32 s; an hour of the rate-limit rollup 19 s, now under one.
--
-- It replaces the date index rather than joining it, so a write updates as
-- many indexes as before.  The new one is built first and the old one dropped
-- after, so a date index is there throughout; db.EventDateIndexHint names
-- whichever the database has.  The columns are the ones those reads take and
-- no more: the fingerprint, the user agent and the payload stay in the table,
-- since carrying them would double the index for the reads that want them.
CREATE INDEX IF NOT EXISTS idx_unmask_event_date_cover
    ON unmask_event (date_created, ip_address, phase, flags, ja4_verdict, ja4_verdict_id);
DROP INDEX IF EXISTS idx_unmask_event_date;
