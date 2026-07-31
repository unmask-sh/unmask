-- 0025 event ref index: make the support lookup stop reading the whole table.
-- See the SQLite copy of this migration for the reasoning and the measurement,
-- including why existing rows are deliberately left unbackfilled.
ALTER TABLE unmask_event
    ADD COLUMN ref_id VARCHAR(32) COMMENT 'support correlation id, copied out of payload_json on write',
    ADD INDEX idx_unmask_event_ref (ref_id);
