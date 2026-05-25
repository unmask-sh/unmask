-- 0010 unmask_event.scheme: see the sqlite counterpart for the rationale.
ALTER TABLE unmask_event ADD COLUMN scheme VARCHAR(8) NOT NULL DEFAULT '';
