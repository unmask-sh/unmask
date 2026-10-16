package settings

import (
	"log"

	"gopkg.in/yaml.v3"
)

// warnRemovedAuditRetention: `audit_retention_days` pruned the admin-action
// log past 90 days by default until 0.1.51.  0.1.52 keeps the log unless a
// retention is set, under its own key (audit_log_retention_days) beside the
// notification list's (notice_retention_days), both on the retention tab.
//
// The old key is ignored, so an install that carried the written default
// keeps its log from now on -- which is the point of the change.  Name it,
// since an operator who set a number of their own would otherwise find the
// log growing with no word why.  Warn only (feedback_no_user_rescue).
func warnRemovedAuditRetention(resolved string, raw []byte) {
	var probe struct {
		Days *int `yaml:"audit_retention_days"`
	}
	if yaml.Unmarshal(raw, &probe) != nil || probe.Days == nil {
		return
	}
	log.Printf("unmask: config %s still carries audit_retention_days: %d -- REMOVED in 0.1.52 and ignored: the audit log "+
		"is kept until a retention is set as audit_log_retention_days (the retention tab, or this file). Delete the old key to silence this.",
		resolved, *probe.Days)
}
