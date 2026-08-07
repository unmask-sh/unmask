-- Reset the hourly aggregate so it backfills with the two counters the landing
-- page needs: hkPhase (per-phase event count) and hkUnruledPoW (the abandon
-- rate's population).  Same shape as 0012 / 0013 / 0014 / 0015.
--
-- Why a reset rather than a forward-only add: the aggregate is accumulated
-- (cnt +=) from a single cursor, so a new bucket kind has no history and a
-- window that straddles the upgrade would read a KPI that is correct for the
-- hours since the restart and zero before it -- a number that looks like a
-- traffic collapse.  The rebuild is one pass over the retained events on the
-- aggregator's own goroutine (~10s on a fleet-sized install), and the page
-- falls back to the raw scan until it finishes.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
