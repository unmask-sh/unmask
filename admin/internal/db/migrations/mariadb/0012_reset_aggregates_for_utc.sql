-- Reset all aggregate tables so they re-fill under the new "all timestamps
-- are UTC" rule.  Pre-rule rows are a mix of server-local and UTC bucketing
-- depending on driver / column / function path, which would render wrong
-- when the read-side query layer starts interpreting unix sec via the
-- operator's cookie TZ.  Cheap to rebuild: AggregateHourly backfills from
-- unmask_event up to its retention window, the nginxlog minute tables
-- repopulate on every datagram, country / HLL sketches likewise.
DELETE FROM unmask_aggregate;
DELETE FROM unmask_aggregate_hourly;
DELETE FROM unmask_aggregate_hll;
DELETE FROM unmask_aggregate_state;
DELETE FROM unmask_cookie_minute;
DELETE FROM unmask_crawler_minute;
DELETE FROM unmask_traffic_country_hourly;
DELETE FROM unmask_traffic_hll;
