package ipgeo

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

// The provider counts are kept by the database's identity (path, size,
// modification time) and the question's digest: the same file answers from
// memory, a file with a new modification time is walked again, and another
// question is its own entry.
func TestASNCountsCachedByFileIdentity(t *testing.T) {
	ASNCountsMemoReset()
	path := writeTestMMDB(t, "Test-ASN", []mmdbEntry{
		{netip.MustParsePrefix("203.0.113.0/24"), asnRecord(64500, "Example Network")},
		{netip.MustParsePrefix("198.51.100.0/24"), asnRecord(64501, "Example Cloud")},
	})
	pats := map[string][]string{"example": {"example"}, "cloud": {"cloud"}}
	nums := map[string][]uint{"direct": {64500}}
	got, err := ASNCountsCached(path, pats, nums)
	if err != nil {
		t.Fatal(err)
	}
	if got["example"] != 2 || got["cloud"] != 1 || got["direct"] != 1 {
		t.Fatalf("counts %v", got)
	}

	// A different database written over the file, with the modification
	// time put back: the same identity, so the kept answer stands.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	other := writeTestMMDB(t, "Test-ASN", []mmdbEntry{
		{netip.MustParsePrefix("203.0.113.0/24"), asnRecord(64500, "Example Network")},
		{netip.MustParsePrefix("198.51.100.0/24"), asnRecord(64502, "Another Cloud")},
	})
	b, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Size() != fi.Size() {
		t.Skip("the two databases differ in size; the identity test needs them equal")
	}
	got, err = ASNCountsCached(path, pats, nums)
	if err != nil {
		t.Fatal(err)
	}
	if got["example"] != 2 {
		t.Errorf("the kept answer was not used: %v", got)
	}
	// The caller's copy is its own.
	got["example"] = 99
	if again, _ := ASNCountsCached(path, pats, nums); again["example"] != 2 {
		t.Errorf("the caller's change reached the memo: %v", again)
	}

	// A new modification time: walked again, and the new file answers.
	if err := os.Chtimes(path, fi.ModTime().Add(2*time.Second), fi.ModTime().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err = ASNCountsCached(path, pats, nums)
	if err != nil {
		t.Fatal(err)
	}
	if got["example"] != 1 || got["cloud"] != 1 {
		t.Errorf("after the file changed: %v", got)
	}

	// Another question is another entry, not the first one's answer.
	got, err = ASNCountsCached(path, map[string][]string{"any": {"a"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["any"] != 2 || got["example"] != 0 {
		t.Errorf("another question: %v", got)
	}
	if n := len(asnCountsMemo); n != 3 {
		t.Errorf("%d entries kept, want 3", n)
	}
	if _, err := ASNCountsCached(path+".none", pats, nums); err == nil {
		t.Error("a missing file is not an error")
	}
}
