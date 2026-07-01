-- 0011 unmask_event.port: see the sqlite counterpart for the rationale.
ALTER TABLE unmask_event ADD COLUMN port INT NOT NULL DEFAULT 0;
