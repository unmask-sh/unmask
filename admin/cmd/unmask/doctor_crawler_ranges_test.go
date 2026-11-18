package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// rangeDocAt writes an aggregated range document generated at the given
// moment that holds every preset with the ranges the built-in snapshot has
// for it, and returns its path.
func rangeDocAt(t *testing.T, generatedAt time.Time) string {
	t.Helper()
	doc := nginxconf.AggregatedDoc{SchemaVersion: 1, GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Sources: map[string]nginxconf.AggregatedSource{}}
	for i := range nginxconf.BypassIPGroups {
		g := &nginxconf.BypassIPGroups[i]
		src := nginxconf.AggregatedSource{CreationTime: generatedAt.UTC().Format("2006-01-02T15:04:05.000000")}
		for _, p := range g.Prefixes() {
			src.Prefixes = append(src.Prefixes, nginxconf.AggregatedPrefix{IPv4Prefix: p})
		}
		doc.Sources[g.ID] = src
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// Doctor's crawler-range check reads two dates: when the range files were
// written, which says the pull runs, and when the document they were written
// from was generated, which says that what the pull is handed is current.
// It read only the first.  A source that keeps answering with the same
// document passes the pull every day -- an equal date is no rollback -- and
// the files are a day old for as long as that lasts, so doctor said "oldest
// sync 1d ago" over data that was months old.
func TestDoctorNamesFreshFilesFromAnOldDocument(t *testing.T) {
	dir := t.TempDir()
	nginxconf.SetOverrideDir(dir)
	t.Cleanup(func() { nginxconf.SetOverrideDir(""); nginxconf.Reload() })
	nginxconf.Reload()

	off := false
	var s settings.Settings
	s.Nginx.BypassIPEnabledPresets = []string{"google-common", "google-special", "google-user-triggered"}
	// The presets are named above; what the auto-from-UA rule would add
	// depends on how old the built-in snapshot is on the day the test runs.
	s.Nginx.BypassIPAutoFromUA = &off
	if len(nginxconf.RangeVerifiedUA(s.Nginx)) == 0 {
		t.Fatal("no crawler UA pattern is range-verified under these settings: the check would say nothing")
	}
	run := func(s settings.Settings, now time.Time) (ok, warn string) {
		t.Helper()
		var oks, warns []string
		checkCrawlerRanges(s, dir, now,
			func(title, m string) { oks = append(oks, title+": "+m) },
			func(title, m string) { warns = append(warns, title+": "+m) })
		if len(oks)+len(warns) != 1 {
			t.Fatalf("the check gave %d lines, want one: ok %q, warn %q", len(oks)+len(warns), oks, warns)
		}
		return strings.Join(oks, ""), strings.Join(warns, "")
	}
	// filesWrittenAt: every file in the directory as a pull at that moment
	// leaves it.
	filesWrittenAt := func(at time.Time) {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil || len(files) < 4 {
			t.Fatalf("%d files in %s (err %v)", len(files), dir, err)
		}
		for _, f := range files {
			if err := os.Chtimes(f, at, at); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Today: a document generated two hours ago, pulled just now.
	today := time.Now()
	doc := rangeDocAt(t, today.Add(-2*time.Hour))
	pull := &nginxconf.Sync{Dir: dir}
	if err := pull.PullFromFile(doc); err != nil {
		t.Fatal(err)
	}
	if ok, warn := run(s, today); warn != "" || !strings.Contains(ok, "oldest sync 0d ago") {
		t.Errorf("a current document, just pulled: ok %q, warn %q", ok, warn)
	}
	// The same document again is taken (it is no rollback), which is how the
	// files stay young.
	if err := pull.PullFromFile(doc); err != nil {
		t.Fatalf("the same document again: %v", err)
	}

	// Sixty days on.  The pull has run every day -- the files were written
	// yesterday -- and was handed that same document each time.
	later := today.Add(60 * 24 * time.Hour)
	filesWrittenAt(later.Add(-24 * time.Hour))
	ok, warn := run(s, later)
	if ok != "" || !strings.Contains(warn, "written 1 day(s) ago, but from a document generated 60 days ago") {
		t.Errorf("files a day old from a document sixty days old: ok %q, warn %q", ok, warn)
	}
	if !strings.Contains(warn, nginxconf.SyncDefaultHubURL) {
		t.Errorf("the warning does not name where the document comes from: %q", warn)
	}
	// An install pointed at its own hub is told to look there.
	own := s
	own.Nginx.SyncHubURL = "https://hub.example.test/ranges.json"
	if _, warn := run(own, later); !strings.Contains(warn, "https://hub.example.test/ranges.json") || strings.Contains(warn, nginxconf.SyncDefaultHubURL) {
		t.Errorf("an install with its own hub: %q", warn)
	}

	// With the pulls switched off the data in use is what is judged, and by
	// the same date: the files' own no longer make it young.
	offS := s
	offS.Nginx.SyncDisabled = true
	if ok, warn := run(offS, later); ok != "" || !strings.Contains(warn, "the range data in use is more than 30 days old") {
		t.Errorf("pulls off, sixty days on: ok %q, warn %q", ok, warn)
	}
	if ok, warn := run(offS, today); warn != "" || !strings.Contains(ok, "was assembled 0 days ago") {
		t.Errorf("pulls off, today: ok %q, warn %q", ok, warn)
	}

	// What the check said before, it still says: files that are themselves
	// old are a pull that has stopped, and a preset with no file was never
	// synced.
	filesWrittenAt(later.Add(-40 * 24 * time.Hour))
	if ok, warn := run(s, later); ok != "" || !strings.Contains(warn, "synced range files are stale") || !strings.Contains(warn, "40 days") {
		t.Errorf("files forty days old: ok %q, warn %q", ok, warn)
	}
	var first string
	for i := range nginxconf.BypassIPGroups {
		if nginxconf.BypassIPGroups[i].ID == "google-special" {
			first = filepath.Base(nginxconf.BypassIPGroups[i].File)
		}
	}
	if err := os.Remove(filepath.Join(dir, first)); err != nil {
		t.Fatal(err)
	}
	if ok, warn := run(s, later); ok != "" || !strings.Contains(warn, "have never been synced") || !strings.Contains(warn, "google-special") {
		t.Errorf("a preset with no file: ok %q, warn %q", ok, warn)
	}

	// Nothing is range-verified: nothing to say.
	no := false
	quiet := s
	quiet.Nginx.SearchBots.RequireRangeVerification = &no
	var lines int
	checkCrawlerRanges(quiet, dir, later, func(string, string) { lines++ }, func(string, string) { lines++ })
	if lines != 0 {
		t.Errorf("with range verification off the check gave %d lines", lines)
	}
}
