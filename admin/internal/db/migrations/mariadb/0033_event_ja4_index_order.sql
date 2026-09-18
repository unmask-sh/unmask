-- 0033 replace the first shape of the fingerprint index (see the sqlite file).
--
-- Conditional both ways, so a database that already has the current 0032 does
-- no work here and the index is built once.
DROP INDEX IF EXISTS idx_unmask_event_ja4_date ON unmask_event;
CREATE INDEX IF NOT EXISTS idx_unmask_event_ja4_phase
    ON unmask_event (ja4, phase, date_created);
