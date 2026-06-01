-- Reset the hourly aggregate so it backfills with the new per-(phase=load,
-- verdict) distinct-IP sketches added for funnelAgg's LoadUniq path (= the
-- hkLoadVerdictIP HLL).  Same shape as 0012 / 0013 / 0014.
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
