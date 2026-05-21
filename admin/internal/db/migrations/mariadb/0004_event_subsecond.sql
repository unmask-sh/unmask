-- 0004 date_created: second precision -> millisecond precision.
--
-- unmask now stamps unmask_event.date_created in Go at ingest time with
-- millisecond precision so same-second events keep their true order in the
-- hunt log.  MariaDB DATETIME defaults to 0 fractional digits and silently
-- truncates the milliseconds, so existing v1-v3 DBs need this widen to
-- DATETIME(3) before the new inserts arrive.
ALTER TABLE unmask_event MODIFY date_created DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3);
