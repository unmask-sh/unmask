-- unmask:deferrable table=unmask_event
--
-- Index-only, so the daemon may leave it for the operator when the table is
-- large (see the package doc of internal/db/migrator.go).
--
-- 0037 event card indexes: the stats page's per-visitor cards read an index of
-- their own rows instead of the event table.
--
-- Those cards -- reload loops, verification failures, CAPTCHA passes, cookie
-- failures, rebind lineages, rate-limited requests -- each want a few percent
-- of the events in their window, and columns no other index carries: the user
-- agent, the reload count, a field of the payload.  Every row they counted was
-- a seek into the table, and the rows of a day lie far apart in a large file:
-- on a database larger than memory, on a disk that seeks, a card took tens of
-- seconds, cold on every visit, and the page reached its 30 s with cards
-- missing (2026-10-14).  The cost grew with the traffic.
--
-- Each index here holds only one card family's rows (a partial index), with
-- the columns those cards read, so they read the index alone: on a test
-- database a reload-loop ranking went from 30 s to 0.04 s, cold.  A
-- write pays for one of these only when its row belongs to it, and the
-- families' phases do not overlap, so most writes pay for none.
--
-- A payload field is indexed as payload_json ->> '$.field', not json_extract:
-- SQLite does not read a json_extract value back from an index (the function
-- may return a JSON subtype the index cannot keep), so a card that named it
-- went to the table for every row again.  ->> returns plain values.
--
-- The payload test keeps a row whose payload is not JSON out of an index that
-- reads the payload, instead of failing the row's write (both raise on
-- malformed text).  The queries name the same terms -- SQLite uses a
-- partial index only for a query that does (db.CardIndexHint and
-- db.CardPayloadTerm), and TestCardIndexesAnswerAsTheTable fails a card whose
-- query stops carrying them.  IF NOT EXISTS so a database that has them passes
-- through without work.
CREATE INDEX IF NOT EXISTS idx_unmask_event_reload
    ON unmask_event (date_created, ip_address, reload_count, flags, user_agent, site, host)
    WHERE phase = 'load' AND reload_count >= 1;
CREATE INDEX IF NOT EXISTS idx_unmask_event_verify_ng
    ON unmask_event (date_created, ip_address, payload_json ->> '$.method', payload_json ->> '$.score', payload_json ->> '$.force_reason', user_agent, ja4_verdict, site, host)
    WHERE phase = 'verify_ng' AND (payload_json IS NULL OR json_valid(payload_json));
CREATE INDEX IF NOT EXISTS idx_unmask_event_captcha_pass
    ON unmask_event (phase, date_created, ip_address, ja4_verdict, ja4, user_agent, payload_json ->> '$.force_reason', payload_json ->> '$.orig_path', site, host)
    WHERE phase IN ('bv_captcha_only','bv_pow_then_captcha') AND (payload_json IS NULL OR json_valid(payload_json));
CREATE INDEX IF NOT EXISTS idx_unmask_event_cookie_fail
    ON unmask_event (date_created, ip_address, user_agent, site, host)
    WHERE phase = 'bv_pow_only' AND (payload_json IS NULL OR json_valid(payload_json)) AND json_extract(payload_json, '$.cookie_set_ok') IN ('false', 0);
CREATE INDEX IF NOT EXISTS idx_unmask_event_rebind
    ON unmask_event (phase, date_created, payload_json ->> '$.lineage', ip_address)
    WHERE phase IN ('bv_rebind','bv_rebind_reject') AND (payload_json IS NULL OR json_valid(payload_json));
CREATE INDEX IF NOT EXISTS idx_unmask_event_rate_limited
    ON unmask_event (date_created, ip_address, user_agent, payload_json ->> '$.orig_path', site, scheme, port, host)
    WHERE phase = 'serve' AND (payload_json IS NULL OR json_valid(payload_json)) AND json_extract(payload_json, '$.rl') IN ('1', 1);
