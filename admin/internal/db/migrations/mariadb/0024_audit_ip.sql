-- 0024 audit ip.  See the sqlite counterpart for the rationale: the audit trail
-- recorded who / when / what but not from where, and nginx's admin access log
-- keeps only the load-balancer hop, so an LB-fronted node wrote the operator's
-- real address down nowhere.
--
-- IF NOT EXISTS keeps this a no-op on a fresh install, where migrate.go has
-- already created the column before the numbered migrations run.
ALTER TABLE unmask_user_audit
    ADD COLUMN IF NOT EXISTS ip VARCHAR(45)
        COMMENT 'client IP the action came from (text, IPv6-capable; NULL for pre-0024 rows and non-HTTP callers)'
        AFTER detail;
