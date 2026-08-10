package communitybans

import (
	"os"
	"path/filepath"
	"testing"
)

// The matcher must see exactly what nginx sees.  It is built by reading back
// the files WriteMapFiles produced, so this walks a feed through the writer and
// asserts every enforcement decision the daemon makes matches the map contents
// -- including the ones the writer deliberately drops.
func TestMatcherMirrorsTheMapFiles(t *testing.T) {
	dir := t.TempDir()
	doc := FeedDocument{
		Version: 2,
		Entries: []FeedEntry{
			{Match: MatchIPJA4, IP: "203.0.113.9", JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", Promoted: true},
			{Match: MatchJA4, JA4: "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb", Promoted: true},
			{Match: MatchIPOnly, IP: "198.51.100.7", Promoted: true},
			{Match: MatchIPOnly, IP: "2001:db8::42", Promoted: true},
			// Not promoted: browse-only, must never enforce on either wire.
			{Match: MatchIPOnly, IP: "192.0.2.1"},
			// Expired: same.
			{Match: MatchIPOnly, IP: "192.0.2.2", Promoted: true, ExpiresAt: 1},
		},
	}
	if err := WriteMapFiles(doc, dir); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name     string
		ip, ja4  string
		wantKind string
		wantHit  bool
	}{
		{"ip+ja4 pair", "203.0.113.9", "t13d1516h2_8daaf6152771_b0da82dd1658", HitKindIPJA4, true},
		{"ip+ja4 pair, wrong ja4", "203.0.113.9", "t13dxxxxh2_000000000000_111111111111", "", false},
		{"ja4 alone, any ip", "192.0.2.250", "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb", HitKindJA4, true},
		{"ip alone, no ja4", "198.51.100.7", "", HitKindIP, true},
		{"ipv6 ip alone", "2001:db8::42", "", HitKindIP, true},
		{"clean client", "192.0.2.99", "t13d0000h1_cccccccccccc_dddddddddddd", "", false},
		{"non-promoted entry never enforces", "192.0.2.1", "", "", false},
		{"expired entry never enforces", "192.0.2.2", "", "", false},
		{"empty client", "", "", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			kind, ok := m.Hit(c.ip, c.ja4)
			if ok != c.wantHit || kind != c.wantKind {
				t.Errorf("Hit(%q,%q) = (%q,%v), want (%q,%v)", c.ip, c.ja4, kind, ok, c.wantKind, c.wantHit)
			}
		})
	}

	// Most specific wins: a client covered by both an ip_ja4 pair and a bare
	// ip entry is reported under the pair, so the operator sees the narrower
	// rule that caught it.
	doc2 := FeedDocument{Version: 2, Entries: []FeedEntry{
		{Match: MatchIPJA4, IP: "203.0.113.9", JA4: "t13dpairh2_111111111111_222222222222", Promoted: true},
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true},
	}}
	dir2 := t.TempDir()
	if err := WriteMapFiles(doc2, dir2); err != nil {
		t.Fatal(err)
	}
	m2, err := LoadMatcher(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if kind, _ := m2.Hit("203.0.113.9", "t13dpairh2_111111111111_222222222222"); kind != HitKindIPJA4 {
		t.Errorf("overlapping entries: kind=%q, want %q", kind, HitKindIPJA4)
	}
}

// A missing map dir (= fresh install, nothing pulled yet) is an empty matcher,
// not an error: the daemon must start and enforce nothing rather than refuse.
func TestLoadMatcherMissingFilesIsEmpty(t *testing.T) {
	m, err := LoadMatcher(t.TempDir())
	if err != nil {
		t.Fatalf("missing map files should not error: %v", err)
	}
	if m.Len() != 0 {
		t.Errorf("Len()=%d, want 0", m.Len())
	}
	if _, ok := m.Hit("203.0.113.9", "t13d"); ok {
		t.Error("empty matcher must not hit")
	}
	if _, err := LoadMatcher(""); err != nil {
		t.Errorf("empty dir should not error: %v", err)
	}
}

// A nil matcher is the un-configured install (no client wired).  It must read
// as "nothing on the feed", never panic -- the forward-auth request path calls
// it on every request.
func TestNilMatcherNeverHits(t *testing.T) {
	var m *Matcher
	if _, ok := m.Hit("203.0.113.9", "t13d"); ok {
		t.Error("nil matcher hit")
	}
	if m.Len() != 0 {
		t.Error("nil matcher reports entries")
	}
}

// Garbage on a line must not take the rest of the file down with it: the
// enforcement set is security-relevant, so a truncated write costs only the
// lines it damaged.
func TestLoadMatcherSkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"# a comment\n" +
		"\n" +
		"not a quoted key 1;\n" +
		"\"198.51.100.7\" 1;\n" +
		"\"unterminated 1;\n" +
		"\"198.51.100.8\" 1;\n"
	if err := os.WriteFile(filepath.Join(dir, MapFileIP), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		if _, ok := m.Hit(ip, ""); !ok {
			t.Errorf("%s should still be enforced despite the malformed neighbours", ip)
		}
	}
	if m.Len() != 2 {
		t.Errorf("Len()=%d, want 2 (malformed lines dropped)", m.Len())
	}
}
