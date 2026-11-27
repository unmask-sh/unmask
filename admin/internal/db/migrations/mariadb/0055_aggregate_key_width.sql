-- 0055 aggregate key width: room for the entry behind a force reason.
--
-- The stats card breaks a force reason down by the entry of the settings
-- that fired, in rollup rows keyed '<force_reason>|<entry>'.  An entry is an
-- operator's own UA pattern, a trap's title, a protected path: the beacon
-- keeps up to 200 characters of one, and bucket_key was VARCHAR(128).
-- Under the default sql_mode (STRICT_TRANS_TABLES) a value longer than its
-- column is an error (1406) that rolls back the chunk the hourly fold is
-- writing, its cursor with it -- so every later pass folded the same chunk
-- into the same error, and no event behind it reached the rollups.
--
-- The fold now cuts a key to the column's width (dashboard.bucketKeyWidth),
-- and this makes the column wide enough to keep what the beacon keeps.
--
-- Not deferrable: the tables hold thirty-two days at most (PruneHourly), and
-- InnoDB extends a VARCHAR whose length prefix stays two bytes (utf8mb4: 128
-- and 255 characters both take two) in place, without copying the table,
-- key columns included.  The PRIMARY KEY stays within InnoDB's 3072 bytes.
--
-- SQLite enforces no declared width and has nothing to change (see its
-- counterpart).
ALTER TABLE unmask_aggregate_hourly
    MODIFY COLUMN bucket_key VARCHAR(255) NOT NULL COMMENT 'key within the family (e.g. <vid>|<verdict>|<phase>), up to dashboard.bucketKeyWidth characters';
ALTER TABLE unmask_aggregate_hll
    MODIFY COLUMN bucket_key VARCHAR(255) NOT NULL COMMENT 'key within the family (e.g. <verdict>, <site>|<verdict>), up to dashboard.bucketKeyWidth characters';
