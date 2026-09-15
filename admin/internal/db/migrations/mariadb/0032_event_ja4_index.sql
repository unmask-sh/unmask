-- 0032 fingerprint index on the event table (see the sqlite file for why).
--
-- The collateral of a fingerprint ban was answered by walking the date index
-- across the whole retention window; (ja4, date_created) answers it with one
-- range seek per fingerprint.
CREATE INDEX IF NOT EXISTS idx_unmask_event_ja4_date
    ON unmask_event (ja4, date_created);
