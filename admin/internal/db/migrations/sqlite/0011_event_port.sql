-- 0011 unmask_event.port: listener port captured at ingest from
-- X-Forwarded-Port.  Pairs with the migration-0010 scheme column so the hunt
-- URL popover can build the full address including a non-default port
-- (= 8443 over https etc.).  0 means "unknown / pre-migration row"; the read
-- side falls back to omitting the port entirely.
ALTER TABLE unmask_event ADD COLUMN port INTEGER NOT NULL DEFAULT 0;
