-- 0032 fingerprint index on the event table (see the sqlite file for why).
--
-- (ja4, phase, date_created): the fingerprint finds the rows, the phase picks
-- the few that answer "who completed the challenge with this", and the date
-- bounds them.
CREATE INDEX IF NOT EXISTS idx_unmask_event_ja4_phase
    ON unmask_event (ja4, phase, date_created);
