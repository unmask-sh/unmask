-- 0045 crawler_named_hourly country: where the requests passed on a crawler's
-- name alone came from.  See the sqlite counterpart for the rationale.
-- Existing rows get country='' (unknown); one ALTER, so a crash leaves the
-- table either as it was or as it will be.
ALTER TABLE unmask_crawler_named_hourly
    ADD COLUMN country VARCHAR(2) NOT NULL DEFAULT '' COMMENT 'ISO 3166-1 alpha-2 of the client address, empty when unknown' AFTER crawler,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (bucket_hour, crawler, country);
