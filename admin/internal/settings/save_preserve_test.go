package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSavePreservesUnknownTopLevelKeys pins the fix for the 2026-07-21
// unmask.sh incident: a Save must carry over top-level sections that belong
// to other programs sharing the config file (feed_server), instead of
// silently dropping them.
func TestSavePreservesUnknownTopLevelKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	orig := `db:
  driver: sqlite
  sqlite_path: ` + filepath.Join(dir, "x.sqlite") + `
# feed_server is unmask-site's block, not ours
feed_server:
  listen: 127.0.0.1:9800
  ai_key: sk-live-XYZ
  nested:
    keep: [1, 2, 3]
`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(s, p); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{"feed_server:", "listen: 127.0.0.1:9800", "ai_key: sk-live-XYZ", "keep:", "not managed by unmask"} {
		if !strings.Contains(body, want) {
			t.Errorf("saved config lost %q\n---\n%s", want, body)
		}
	}
	// The preserved block must survive a SECOND save cycle too (load the
	// saved file, save again) — the incident shape was repeated hourly saves.
	s2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(s2, p); err != nil {
		t.Fatal(err)
	}
	got2, _ := os.ReadFile(p)
	if !strings.Contains(string(got2), "ai_key: sk-live-XYZ") {
		t.Error("second save cycle dropped the preserved block")
	}
	if n := strings.Count(string(got2), "feed_server:"); n != 1 {
		t.Errorf("feed_server duplicated: %d occurrences", n)
	}
	// Known sections must never be duplicated into the preserved tail.
	if n := strings.Count(string(got2), "\ndb:"); n != 1 {
		t.Errorf("db section occurrences = %d, want 1", n)
	}
}

// TestSaveNoUnknownKeysNoTail: a config with only known sections gets no
// preservation banner (byte-noise-free for the common case).
func TestSaveNoUnknownKeysNoTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte("db:\n  driver: sqlite\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(s, p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if strings.Contains(string(got), "not managed by unmask") {
		t.Error("preservation banner must not appear when nothing is preserved")
	}
}

// TestSettingsTopLevelKeysCoverEveryYamlSection: every field must resolve to
// a non-empty yaml key so a future tag-less field can't silently open a
// duplicate-key hole in the preservation logic.
func TestSettingsTopLevelKeysCoverEveryYamlSection(t *testing.T) {
	keys := settingsTopLevelKeys()
	for _, want := range []string{"db", "secret", "challenge", "nginx", "rate_limit", "community_bans"} {
		if !keys[want] {
			t.Errorf("settingsTopLevelKeys missing %q", want)
		}
	}
}
