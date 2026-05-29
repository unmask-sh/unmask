package communitybans

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// 66.249.64.0/19 is Googlebot's real range, so the test doubles as a check on
// the exact accident the guard prevents.  (The matcher itself is covered in
// nginxconf/ipbypass_test.go; here we only exercise the entry filter.)
func TestExcludeBypassedEntries(t *testing.T) {
	var s settings.Settings
	s.Nginx.BypassIPs = []string{"66.249.64.0/19"}
	m := NewBypassMatcher(s)

	entries := []FeedEntry{
		{Match: MatchIPOnly, IP: "66.249.66.1"},      // crawler -> drop
		{Match: MatchIPJA4, IP: "1.2.3.4", JA4: "x"}, // keep
		{Match: MatchJA4, JA4: "ja4only"},            // no IP -> keep (map-only)
		{Match: MatchIPOnly, IP: "66.249.80.9"},      // crawler -> drop
	}
	kept, skipped := excludeBypassedEntries(entries, m)
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	for _, e := range kept {
		if e.IP == "66.249.66.1" || e.IP == "66.249.80.9" {
			t.Errorf("crawler IP %s leaked into the enforced set", e.IP)
		}
	}
}

func TestExcludeBypassedEntriesNoConfig(t *testing.T) {
	// No bypass config -> matcher is empty and every entry is kept.
	m := NewBypassMatcher(settings.Settings{})
	entries := []FeedEntry{{Match: MatchIPOnly, IP: "1.2.3.4"}}
	kept, skipped := excludeBypassedEntries(entries, m)
	if skipped != 0 || len(kept) != 1 {
		t.Fatalf("no-bypass: kept=%d skipped=%d, want 1/0", len(kept), skipped)
	}
}
