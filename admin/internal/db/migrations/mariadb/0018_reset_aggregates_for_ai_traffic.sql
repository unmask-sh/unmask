-- WITHDRAWN.  See the sqlite counterpart for the full reasoning; the short
-- version is that wholesale aggregate resets stall every dashboard query
-- for 30-60 minutes on installs of any meaningful size, and the right move
-- is to add new bucket_kinds incrementally instead.  The file remains so
-- the migration number stays monotonically allocated; the body is a
-- no-op marker.
SELECT 1 WHERE 0;
