package ipgeo

import (
	"net/netip"
	"testing"
)

// TestLookupBytesForms: the packed forms the event table stores (4 and 16
// bytes) resolve like the string, and any other width is no address.
func TestLookupBytesForms(t *testing.T) {
	r := Open(testCountryDB(t), "")
	defer r.Close()
	if got := r.LookupBytes([]byte{203, 0, 113, 4}); got != "JP" {
		t.Fatalf("4-byte form: %q", got)
	}
	v4in16 := netip.MustParseAddr("::ffff:198.51.100.7").As16()
	if got := r.LookupBytes(v4in16[:]); got != "US" {
		t.Fatalf("16-byte form: %q", got)
	}
	if got := r.LookupBytes([]byte{1, 2, 3}); got != "" {
		t.Fatalf("3 bytes: %q", got)
	}
	if got := r.LookupBytes(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
}

// TestReloadSwitchesDatabases: a reload to another file answers from that
// file, to "" answers nothing, and an unchanged path is left alone.
func TestReloadSwitchesDatabases(t *testing.T) {
	first := testCountryDB(t)
	second := writeTestMMDB(t, "Other-Country", []mmdbEntry{
		{netip.MustParsePrefix("203.0.113.0/24"), countryRecord("DE", "Germany")},
	})
	r := Open(first, "")
	defer r.Close()
	if got := r.Lookup("203.0.113.1"); got != "JP" {
		t.Fatalf("first: %q", got)
	}
	r.Reload(second, "")
	if got := r.Lookup("203.0.113.1"); got != "DE" {
		t.Fatalf("after reload to the second file: %q (the cache was not dropped?)", got)
	}
	r.Reload("", "")
	if r.Loaded() || r.Lookup("203.0.113.1") != "" {
		t.Fatalf("after reload to no file: loaded=%v", r.Loaded())
	}
	r.Reload(second, "")
	if !r.Loaded() {
		t.Fatal("after reload back: not loaded")
	}
	r.Reload(second, "") // unchanged: nothing closed
	if got := r.Lookup("203.0.113.1"); got != "DE" {
		t.Fatalf("after an unchanged reload: %q", got)
	}
	r.Reload("/nonexistent/path.mmdb", "")
	if r.Loaded() || r.Lookup("203.0.113.1") != "" {
		t.Fatal("a file that cannot be opened still reports loaded")
	}
}

// TestSuggestASNOverTheDatabase: the suggestion index is built from the ASN
// database on first use, finds the organization by a prefix of its name and
// by its number, and is rebuilt after a reload.
func TestSuggestASNOverTheDatabase(t *testing.T) {
	r := Open("", testASNDB(t))
	defer r.Close()
	got := r.SuggestASN("exam", 5)
	if len(got) == 0 {
		t.Fatal("no suggestion for the organization's prefix")
	}
	foundOrg := false
	for _, s := range got {
		if s.Kind == "org" && s.Org == "Example Network" && len(s.ASNs) == 1 && s.ASNs[0] == 64500 {
			foundOrg = true
		}
	}
	if !foundOrg {
		t.Fatalf("suggestions: %+v", got)
	}
	byNumber := r.SuggestASN("64500", 5)
	foundASN := false
	for _, s := range byNumber {
		if s.Kind == "asn" && s.ASN == 64500 {
			foundASN = true
		}
	}
	if !foundASN {
		t.Fatalf("by number: %+v", byNumber)
	}
	if got := r.SuggestASN("   ", 5); got != nil {
		t.Fatalf("blank query: %+v", got)
	}
	r.Reload("", "")
	if got := r.SuggestASN("exam", 5); got != nil {
		t.Fatalf("with no ASN database: %+v", got)
	}
}
