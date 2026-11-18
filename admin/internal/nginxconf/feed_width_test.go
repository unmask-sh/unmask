package nginxconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// googleCommon: the preset the tests below feed.
func googleCommon(t *testing.T) *BypassIPGroup {
	t.Helper()
	for i := range BypassIPGroups {
		if BypassIPGroups[i].ID == "google-common" {
			return &BypassIPGroups[i]
		}
	}
	t.Fatal("no google-common group")
	return nil
}

// A crawler-range document is taken on its signature and on the share of the
// ranges it keeps.  Neither says anything of a source that gained one row:
// with 0.0.0.0/0 among Google's ranges every client is "Google's", and
// passes without a challenge on every site that has the preset on.  A source
// with a range no vendor could mean is refused, and the ranges in use stay.
func TestBypassSourceWiderThanAVendorsIsRefused(t *testing.T) {
	g := googleCommon(t)
	var n settings.Nginx
	n.BypassIPEnabledPresets = []string{"google-common"}
	nobody := "198.51.100.7"

	for _, wide := range []string{"0.0.0.0/0", "128.0.0.0/1", "10.0.0.0/7", "::/0", "2000::/3", "::ffff:0:0/96"} {
		dir := t.TempDir()
		SetOverrideDir(dir)
		Reload()
		src := AggregatedSource{CreationTime: time.Now().UTC().Format("2006-01-02T15:04:05.000000")}
		for _, p := range g.Prefixes() {
			src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv4Prefix: p})
		}
		real := len(src.Prefixes)
		if strings.Contains(wide, ":") {
			src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv6Prefix: wide})
		} else {
			src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv4Prefix: wide})
		}
		b, err := json.Marshal(AggregatedDoc{SchemaVersion: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Sources: map[string]AggregatedSource{"google-common": src}})
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "doc.json")
		if err := os.WriteFile(f, b, 0o644); err != nil {
			t.Fatal(err)
		}
		err = (&Sync{Dir: dir}).PullFromFile(f)
		if err == nil || !strings.Contains(err.Error(), "wider than a feed may") {
			t.Errorf("%s among %d real ranges: err %v, want the source refused", wide, real, err)
		}
		if _, serr := os.Stat(filepath.Join(dir, filepath.Base(g.File))); serr == nil {
			t.Errorf("%s: the source was written to the directory all the same", wide)
		}
		if NewIPBypassMatcher(n).Match(nobody) {
			t.Errorf("%s: an address of nobody's passes as the crawler's", wide)
		}
		if got := g.PrefixCount(); got != real {
			t.Errorf("%s: the preset holds %d ranges, want the %d in use before", wide, got, real)
		}
	}
	SetOverrideDir("")
	Reload()

	// A file that is already on disk -- a daemon from before this check
	// wrote it, or a hand did -- is read by the same rule: the wide row is
	// left out, the rest are the preset's.
	dir := t.TempDir()
	type row struct {
		IPv4Prefix string `json:"ipv4Prefix,omitempty"`
		IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	}
	payload := struct {
		CreationTime string `json:"creationTime"`
		Prefixes     []row  `json:"prefixes"`
	}{CreationTime: time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		Prefixes: []row{{IPv4Prefix: "0.0.0.0/0"}, {IPv4Prefix: "192.0.2.0/24"}, {IPv6Prefix: "::/0"}, {IPv6Prefix: "2001:db8:77::/48"}}}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(g.File)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	SetOverrideDir(dir)
	t.Cleanup(func() { SetOverrideDir(""); Reload() })
	Reload()
	if got := strings.Join(g.Prefixes(), " "); got != "192.0.2.0/24 2001:db8:77::/48" {
		t.Errorf("a file on disk with two wide rows: the preset holds %q, want the two real ranges", got)
	}
	m := NewIPBypassMatcher(n)
	if m.Match(nobody) || m.Match("2001:db8:99::1") {
		t.Error("a wide row in a file on disk passes an address of nobody's")
	}
	if !m.Match("192.0.2.9") || !m.Match("2001:db8:77::9") {
		t.Error("the real ranges of that file do not match")
	}
}

// A source without such a row is taken as before, a vendor's whole /8
// included: the floor is the widest block any one holder has.
func TestBypassSourceAtTheFloorIsTaken(t *testing.T) {
	g := googleCommon(t)
	dir := t.TempDir()
	SetOverrideDir(dir)
	t.Cleanup(func() { SetOverrideDir(""); Reload() })
	Reload()
	src := AggregatedSource{CreationTime: time.Now().UTC().Format("2006-01-02T15:04:05.000000")}
	for _, p := range g.Prefixes() {
		src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv4Prefix: p})
	}
	src.Prefixes = append(src.Prefixes, AggregatedPrefix{IPv4Prefix: "17.0.0.0/8"}, AggregatedPrefix{IPv6Prefix: "2001::/16"}, AggregatedPrefix{IPv4Prefix: "203.0.113.9"})
	b, err := json.Marshal(AggregatedDoc{SchemaVersion: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Sources: map[string]AggregatedSource{"google-common": src}})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&Sync{Dir: dir}).PullFromFile(f); err != nil {
		t.Fatalf("a source with a /8, an IPv6 /16 and a single address: %v", err)
	}
	var n settings.Nginx
	n.BypassIPEnabledPresets = []string{"google-common"}
	if m := NewIPBypassMatcher(n); !m.Match("17.1.2.3") || !m.Match("203.0.113.9") || m.Match("198.51.100.7") {
		t.Error("the source at the floor was not taken as it is")
	}
}
