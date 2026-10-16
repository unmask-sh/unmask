package settings

import (
	"path/filepath"
	"testing"
)

// 0 = "retain forever" and publish_country=false = "don't publish my country"
// are meaningful zero values.  omitempty used to drop them on Save, so the next
// Load re-defaulted (90 days / publish=true) -- silently deleting the history an
// operator chose to keep and re-leaking the country they opted out of.  They
// must survive a Save -> Load round-trip.
func TestSettings_ZeroValueOptOutsRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yml")
	s := defaults()
	s.EventsRetentionDays = 0              // forever
	s.AuditLogRetentionDays = 0            // forever (the default since 0.1.52)
	s.NoticeRetentionDays = 30             // a number of the operator's own
	s.CommunityBans.PublishCountry = false // privacy opt-out

	if err := Save(s, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.EventsRetentionDays != 0 {
		t.Errorf("EventsRetentionDays = %d, want 0 (reverted to default)", got.EventsRetentionDays)
	}
	if got.AuditLogRetentionDays != 0 {
		t.Errorf("AuditLogRetentionDays = %d, want 0 (reverted to default)", got.AuditLogRetentionDays)
	}
	if got.NoticeRetentionDays != 30 {
		t.Errorf("NoticeRetentionDays = %d, want 30", got.NoticeRetentionDays)
	}
	if got.CommunityBans.PublishCountry {
		t.Error("CommunityBans.PublishCountry = true, want false (privacy opt-out reverted)")
	}
}
