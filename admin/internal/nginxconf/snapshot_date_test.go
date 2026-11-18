package nginxconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// datedRangeDoc: an aggregated document with the given generatedAt whose one
// source keeps every range the built-in snapshot has for it, so the
// retention guard has nothing to say.
func datedRangeDoc(t *testing.T, generatedAt time.Time) string {
	t.Helper()
	var g *BypassIPGroup
	for i := range BypassIPGroups {
		if BypassIPGroups[i].ID == "google-common" {
			g = &BypassIPGroups[i]
		}
	}
	if g == nil {
		t.Fatal("no google-common group")
	}
	src := AggregatedSource{CreationTime: time.Now().UTC().Format("2006-01-02T15:04:05.000000")}
	for _, p := range g.Prefixes() {
		src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv4Prefix: p})
	}
	b, err := json.Marshal(AggregatedDoc{SchemaVersion: 1, GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Sources: map[string]AggregatedSource{"google-common": src}})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// The synced range data is as old as the document it was taken from, not as
// old as the write that put it on disk.  A pull rewrites the files, and the
// newest file's date used to count as well: a document three months old,
// served again every day, kept the data "fresh", so the ceiling on what the
// auto-from-UA rule derives from never applied and doctor never warned.
func TestSyncedDataIsAsOldAsItsDocument(t *testing.T) {
	dir := t.TempDir()
	SetOverrideDir(dir)
	t.Cleanup(func() { SetOverrideDir(""); Reload() })
	Reload()
	now := time.Now()
	old := now.Add(-90 * 24 * time.Hour)
	s := &Sync{Dir: dir}
	f := datedRangeDoc(t, old)
	if err := s.PullFromFile(f); err != nil {
		t.Fatalf("the first pull: %v", err)
	}
	// The same document again: an equal date is no rollback, and the files
	// are written anew.
	if err := s.PullFromFile(f); err != nil {
		t.Fatalf("the same document again: %v", err)
	}
	at := overrideDataAt(dir)
	if d := at.Sub(old); d < -time.Second || d > time.Second {
		t.Errorf("the synced copy is dated %s, want the document's own date %s (the files were written just now)",
			at.UTC().Format(time.RFC3339), old.UTC().Format(time.RFC3339))
	}
	if snapshotFreshEnough(at, now) {
		t.Error("a document 90 days old, pulled just now, counts as fresh enough to derive from")
	}
	if d := SyncedDocumentAt().Sub(old); d < -time.Second || d > time.Second {
		t.Errorf("SyncedDocumentAt = %s, want the document's date", SyncedDocumentAt().UTC().Format(time.RFC3339))
	}

	// A current document: fresh, and dated as it says.
	recent := now.Add(-2 * time.Hour)
	if err := s.PullFromFile(datedRangeDoc(t, recent)); err != nil {
		t.Fatalf("a current document: %v", err)
	}
	if at := overrideDataAt(dir); !snapshotFreshEnough(at, now) || at.Sub(recent) > time.Second || recent.Sub(at) > time.Second {
		t.Errorf("after a current document the synced copy is dated %s, want %s", at.UTC().Format(time.RFC3339), recent.UTC().Format(time.RFC3339))
	}

	// An install that synced before pulls recorded the date has only the
	// files to go by: they stand in for it, as before.
	if err := os.Remove(filepath.Join(dir, snapshotMetaBase)); err != nil {
		t.Fatal(err)
	}
	if at := overrideDataAt(dir); now.Sub(at) > time.Minute || at.Sub(now) > time.Minute {
		t.Errorf("with no record of the document's date the files' own (just written) stand in: got %s", at.UTC().Format(time.RFC3339))
	}
	if !SyncedDocumentAt().IsZero() {
		t.Error("SyncedDocumentAt names a date with no record of one")
	}
	if !overrideDataAt("").IsZero() || !overrideDataAt(t.TempDir()).IsZero() {
		t.Error("no synced copy: a date all the same")
	}
}

// A document dated ahead of the clock is not taken: its date is what the
// data's age is read from and what the next document is compared with, so
// one dated next year would never grow old and would turn every real
// document after it away as a rollback.
func TestADocumentFromTheFutureIsRefused(t *testing.T) {
	dir := t.TempDir()
	SetOverrideDir(dir)
	t.Cleanup(func() { SetOverrideDir(""); Reload() })
	Reload()
	now := time.Now()
	s := &Sync{Dir: dir}
	err := s.PullFromFile(datedRangeDoc(t, now.Add(48*time.Hour)))
	if err == nil || !strings.Contains(err.Error(), "ahead of this host's clock") {
		t.Fatalf("a document dated two days ahead: err %v, want it refused", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, snapshotMetaBase)); serr == nil {
		t.Error("the refused document left a record of its date")
	}
	// A clock that is a little off is not a reason to refuse.
	if err := s.PullFromFile(datedRangeDoc(t, now.Add(time.Hour))); err != nil {
		t.Fatalf("a document dated an hour ahead: %v", err)
	}
	// And a real document after it is taken as usual.
	if err := s.PullFromFile(datedRangeDoc(t, now.Add(2*time.Hour))); err != nil {
		t.Fatalf("the next document: %v", err)
	}
}
