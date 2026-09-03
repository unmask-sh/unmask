package advisor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// scheduleHarness seeds a database with one loud two-signal address (worth a
// digest) and one single-signal address (page-only), and collects digests.
func scheduleHarness(t *testing.T) (*db.DB, *[]Digest, Deps) {
	t.Helper()
	d := newTestDB(t)
	for i := 0; i < 40; i++ {
		insertEvent(t, d, "203.0.113.10", "t13d_bot", "serve", "curl/8", `{"path":"/.env"}`)
	}
	for i := 0; i < 40; i++ {
		insertEvent(t, d, "203.0.113.20", "t13d_two", "serve", "curl/8", "")
	}
	var got []Digest
	deps := Deps{
		DB:     d,
		Cfg:    func() settings.AIAdvisorConfig { return settings.AIAdvisorConfig{NotifyEnabled: true} },
		Notify: func(dg Digest) { got = append(got, dg) },
	}
	return d, &got, deps
}

func TestDigestAnnouncesOnlyNewTargets(t *testing.T) {
	_, got, deps := scheduleHarness(t)

	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("expected one digest, got %d", len(*got))
	}
	first := (*got)[0]
	if len(first.New) == 0 {
		t.Fatal("first digest carried no candidates")
	}
	// Everything announced must clear the default score floor (two signals).
	for _, c := range first.New {
		if c.Score < 6 {
			t.Errorf("candidate below the score floor was announced: %+v", c)
		}
	}

	// A second pass over the same data must stay silent: the targets are known.
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("a repeat pass must not re-announce: %d digests", len(*got))
	}
}

// A target whose suppression has aged out becomes news again -- otherwise a
// scanner that goes quiet for a month and returns would never be reported.
func TestDigestReannouncesAfterTTL(t *testing.T) {
	d, got, deps := scheduleHarness(t)
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("setup: expected 1 digest, got %d", len(*got))
	}
	// Age every suppression past the TTL.
	old := time.Now().UTC().Add(-notifiedTTL - time.Hour).Unix()
	if err := d.Gorm.Model(&db.AdvisorNotified{}).Where("1=1").
		Update("notified_at", old).Error; err != nil {
		t.Fatal(err)
	}
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("an aged-out target should be announced again, got %d digests", len(*got))
	}
}

// The score floor is what keeps a single scanner-path hit out of an alert.
func TestDigestScoreFloor(t *testing.T) {
	d := newTestDB(t)
	// One signal only (scanner paths, no hammering volume).
	for _, p := range []string{"/.env", "/wp-config.php", "/.git/config"} {
		insertEvent(t, d, "203.0.113.30", "t13d_scan", "serve", "curl/8", `{"path":"`+p+`"}`)
	}
	var got []Digest
	deps := Deps{
		DB:     d,
		Cfg:    func() settings.AIAdvisorConfig { return settings.AIAdvisorConfig{NotifyEnabled: true} },
		Notify: func(dg Digest) { got = append(got, dg) },
	}
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a single-signal candidate must not raise an alert: %+v", got)
	}
	// Lowering the floor lets it through, so the suppression is the threshold
	// and not a bug in the pass.
	deps.Cfg = func() settings.AIAdvisorConfig {
		return settings.AIAdvisorConfig{NotifyEnabled: true, NotifyMinScore: 3}
	}
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected the candidate at floor 3, got %d digests", len(got))
	}
}

// Recording happens even with no delivery configured, so switching notifications
// on later does not produce a flood of everything ever seen.
func TestDigestRecordsWithoutNotifier(t *testing.T) {
	d, _, deps := scheduleHarness(t)
	deps.Notify = nil
	if err := RunDigestOnce(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	var rows []db.AdvisorNotified
	if err := d.Gorm.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the pass must record what it saw even with no delivery")
	}
}

func TestFormatDigest(t *testing.T) {
	d := Digest{
		Total: 9,
		New: []Candidate{{
			Type: "ip", Target: "203.0.113.10", Score: 6,
			Signals: []Signal{{ID: "challenge_hammering"}, {ID: "scanner_paths"}},
			Serves:  936, Passes: 0, ScannerHits: 405, ASNOrg: "ExampleHost",
		}},
	}
	out := FormatDigest(d, "https://admin.example/unmask/admin/advisor/")
	for _, want := range []string{
		"1 new ban candidate(s)", "9 candidate(s) in total",
		"203.0.113.10", "challenge_hammering, scanner_paths",
		"936 challenges served", "405 scanner-path hits", "ExampleHost",
		"Nothing has been blocked", "https://admin.example/unmask/admin/advisor/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("digest body missing %q:\n%s", want, out)
		}
	}
}

func TestResolvedScheduleDefaults(t *testing.T) {
	var c settings.AIAdvisorConfig
	if c.ResolvedNotifyInterval() != 24*time.Hour {
		t.Errorf("default interval = %v", c.ResolvedNotifyInterval())
	}
	if c.ResolvedNotifyMinScore() != 6 {
		t.Errorf("default min score = %d", c.ResolvedNotifyMinScore())
	}
	c.NotifyIntervalHours = 999999
	if c.ResolvedNotifyInterval() != 24*time.Hour {
		t.Errorf("an out-of-range interval should fall back to 24h, got %v", c.ResolvedNotifyInterval())
	}
	if c.NotifyActive() {
		t.Error("the schedule must be off by default")
	}
}
