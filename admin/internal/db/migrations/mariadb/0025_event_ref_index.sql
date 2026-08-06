-- 0025 event ref index: make the support lookup stop reading the whole table.
-- See the SQLite copy of this migration for the reasoning and the measurement,
-- including why existing rows are deliberately left unbackfilled.
--
-- Column and index are separate statements on purpose: when one of them
-- already exists (a development binary ran an earlier form of the change),
-- the runner skips just that statement and still applies the other.  Combined
-- into one ALTER, a duplicate column would take the index down with it.
ALTER TABLE unmask_event
    ADD COLUMN ref_id VARCHAR(32) COMMENT 'support correlation id, copied out of payload_json on write';
ALTER TABLE unmask_event
    ADD INDEX idx_unmask_event_ref (ref_id);
