package handlers

import (
	"io"
	"testing"

	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The advisor page must render with the shared template set — a field typo or
// a broken pipeline in advisor.html would otherwise only surface on the first
// live click.
func TestAdvisorTemplateRenders(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Lang":     i18n.Lang("en"),
		"TZ":       "UTC",
		"BasePath": "/unmask",
		"Version":  "test",
		"WindowH":  24,
		"Candidates": []advisor.Candidate{
			{
				Type: "ip", Target: "203.0.113.9", Scope: "ip_only", JA4: "t13d_x",
				UA:      "curl/8",
				Signals: []advisor.Signal{{ID: "challenge_hammering", Detail: "42 serves", Weight: 3}},
				Score:   3, Serves: 42, Passes: 0,
				FirstSeen: "2026-09-03 00:00:00", LastSeen: "2026-09-03 01:00:00",
				ASNOrg: "ExampleHost", Country: "US",
				SamplePaths: []string{"/.env"},
			},
			{
				Type: "ja4", Target: "q13d_herd", Scope: "ja4_only",
				Signals: []advisor.Signal{{ID: "ja4_herd", Detail: "12 addresses", Weight: 3}},
				Score:   3, Serves: 60, Passes: 0, DistinctIPs: 12,
				FirstSeen: "2026-09-03 00:00:00", LastSeen: "2026-09-03 01:00:00",
			},
		},
		"EngineErr":             "",
		"Saved":                 false,
		"Dismissed":             false,
		"CommunityBansActive":   false,
		"BanDialogReasonAlways": true,
		"CSRFToken":             "tok",
		"NavCommunityBadge":     0,
		"Me":                    nil,
		"MeName":                "",
		"Hosts":                 nil,
		"HostSelected":          "",
		"SelfHostID":            "",
		"Sites":                 nil,
		"SiteSelected":          "",
	}
	if err := tmpl.ExecuteTemplate(io.Discard, "advisor.html", data); err != nil {
		t.Fatalf("advisor.html render: %v", err)
	}
}

// The dismiss store must upsert on (target_type, target): a second dismissal
// updates the row instead of erroring on the unique key.
func TestAdvisorDismissUpsert(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/a.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	save := func(by string, at int64) {
		row := db.AdvisorDismiss{TargetType: "ip", Target: "203.0.113.9", DismissedBy: by, DismissedAt: at}
		if err := d.Gorm.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_type"}, {Name: "target"}},
			DoUpdates: clause.AssignmentColumns([]string{"dismissed_by", "dismissed_at"}),
		}).Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	save("alice", 100)
	save("bob", 200)

	var rows []db.AdvisorDismiss
	if err := d.Gorm.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after upsert, got %d", len(rows))
	}
	if rows[0].DismissedBy != "bob" || rows[0].DismissedAt != 200 {
		t.Errorf("upsert did not update: %+v", rows[0])
	}
}
