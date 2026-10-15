-- unmask:deferrable table=unmask_event
--
-- Index-only, so the daemon may leave it for the operator when the table is
-- large (see the package doc of internal/db/migrator.go).
--
-- 0039 community-feed serve index: the Community Bans tab's "past 30 days"
-- figure reads an index of its own rows instead of the event table.
--
-- The figure counts the serve events of the window that the shared feed sent
-- to a challenge (payload force_reason=community_bans), and their distinct
-- addresses.  Those rows are a small fraction of the window's serves, and the
-- field that names them sits in the payload: the count was a read of every
-- serve row of thirty days with a JSON parse per row, which on a database
-- larger than memory on a seeking disk outlasted its two-minute budget every
-- time (2026-10-15).  A partial index over just those rows, carrying the time
-- and the address, answers the count and the distinct addresses from the
-- index alone; a write pays for it only when its row belongs to it.
--
-- The payload test keeps a row whose payload is not JSON out of the index
-- instead of failing the row's write, as the card indexes of 0037 do.  The
-- query names the same terms (internal/handlers/community_hits.go): SQLite
-- uses a partial index only for a query that does, and
-- TestCommunityHitsIndexAnswersAsTheTable fails the query when it stops
-- carrying them.  IF NOT EXISTS so a database that has it passes through
-- without work.
CREATE INDEX IF NOT EXISTS idx_unmask_event_community_bans
    ON unmask_event (date_created, ip_address)
    WHERE phase = 'serve' AND (payload_json IS NULL OR json_valid(payload_json)) AND json_extract(payload_json, '$.force_reason') = 'community_bans';
