package communitybans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The feed's entries become keys of an nginx map that nginx loads as root,
// and quoting does not make a key inert: "default", "~..." and "include ..."
// keep their meaning inside quotes.  Only an address that parses and a JA4 of
// the expected shape are written; a feed that says anything else is dropped.
func TestWriteMapFilesDropsEntriesThatAreNotKeys(t *testing.T) {
	dir := t.TempDir()
	doc := FeedDocument{
		Version: 2,
		Entries: []FeedEntry{
			// Kept.
			{Match: MatchIPJA4, IP: "203.0.113.9", JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", Promoted: true},
			{Match: MatchJA4, JA4: "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb", Promoted: true},
			{Match: MatchIPOnly, IP: "198.51.100.7", Promoted: true},
			{Match: MatchIPOnly, IP: "2001:db8::42", Promoted: true},
			// Dropped: map keywords and syntax in place of a value.
			{Match: MatchIPOnly, IP: "default", Promoted: true},
			{Match: MatchIPOnly, IP: "~.*", Promoted: true},
			{Match: MatchIPOnly, IP: `1.2.3.4"; include /etc/evil.conf; #`, Promoted: true},
			{Match: MatchIPOnly, IP: "203.0.113.0/24", Promoted: true},
			{Match: MatchIPOnly, IP: "fe80::1%eth0", Promoted: true},
			{Match: MatchJA4, JA4: "default", Promoted: true},
			{Match: MatchJA4, JA4: "~^t13d", Promoted: true},
			{Match: MatchJA4, JA4: "include /etc/evil.conf", Promoted: true},
			{Match: MatchJA4, JA4: "T13D1516H2_8DAAF6152771_B0DA82DD1658", Promoted: true},
			{Match: MatchIPJA4, IP: "203.0.113.9", JA4: "hostnames", Promoted: true},
			{Match: MatchIPJA4, IP: "volatile", JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", Promoted: true},
		},
	}
	if err := WriteMapFiles(doc, dir); err != nil {
		t.Fatal(err)
	}
	var all string
	for _, name := range []string{MapFileIPJA4, MapFileJA4, MapFileIP} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		all += string(b)
	}
	for _, want := range []string{
		`"203.0.113.9:t13d1516h2_8daaf6152771_b0da82dd1658" 1;`,
		`"t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb" 1;`,
		`"198.51.100.7" 1;`,
		`"2001:db8::42" 1;`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("map files lack %s", want)
		}
	}
	for _, bad := range []string{"default", "~", "include", "hostnames", "volatile", "/24", "%eth0", "T13D", "evil"} {
		for _, line := range strings.Split(all, "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, bad) {
				t.Errorf("map files carry %q in %q", bad, line)
			}
		}
	}
	// Each file has exactly its one kept entry plus the header line.
	for name, n := range map[string]int{MapFileIPJA4: 1, MapFileJA4: 1, MapFileIP: 2} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if got := strings.Count(string(b), " 1;"); got != n {
			t.Errorf("%s: %d entries, want %d:\n%s", name, got, n, b)
		}
	}
}
