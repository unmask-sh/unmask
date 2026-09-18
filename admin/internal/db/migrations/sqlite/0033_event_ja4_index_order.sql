-- 0033 replace the first shape of the fingerprint index.
--
-- 0032 first shipped as (ja4, date_created) and was measured not to help the
-- consultation it was written for: the candidates are the busiest
-- fingerprints, so narrowing to them still read most of the table.  0032 now
-- creates (ja4, phase, date_created) instead; this file is for the databases
-- that already recorded 0032 and so will never run it again.
--
-- Both statements are conditional, so a database that gets the current 0032
-- passes through here without work: nothing to drop, nothing to create.  The
-- index is therefore built once on any one database, which matters because
-- building it takes a write lock for as long as the build runs.
DROP INDEX IF EXISTS idx_unmask_event_ja4_date;
CREATE INDEX IF NOT EXISTS idx_unmask_event_ja4_phase ON unmask_event(ja4, phase, date_created);
