package relay

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doc(t *testing.T, gen string, countries map[string][]string) []byte {
	t.Helper()
	b, err := json.Marshal(Doc{SchemaVersion: 1, GeneratedAt: gen, Relays: map[string]Entry{
		"apple-private-relay": {Name: "iCloud Private Relay", Countries: countries},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLookup(t *testing.T) {
	tb, err := Parse(doc(t, "2026-10-13T00:00:00Z", map[string][]string{
		"JP": {"172.224.226.0/27", "2a02:26f7:b3c0:4000::/64"},
		"GB": {"172.224.226.32/31"},
		"x1": {"192.0.2.0/24"}, // not a country: skipped
		"US": {"not-a-prefix"}, // skipped
	}))
	if err != nil {
		t.Fatal(err)
	}
	if tb.Prefixes != 3 || tb.Countries != 2 {
		t.Errorf("prefixes %d countries %d, want 3 and 2", tb.Prefixes, tb.Countries)
	}
	for _, c := range []struct {
		ip, cc string
	}{
		{"172.224.226.0", "JP"},
		{"172.224.226.31", "JP"},
		{"172.224.226.32", "GB"},
		{"172.224.226.33", "GB"},
		{"172.224.226.34", ""},
		{"172.224.225.255", ""},
		{"::ffff:172.224.226.5", "JP"}, // IPv4-mapped
		{"2a02:26f7:b3c0:4000::1", "JP"},
		{"2a02:26f7:b3c0:4000:ffff:ffff:ffff:ffff", "JP"},
		{"2a02:26f7:b3c0:4001::", ""},
		{"192.0.2.1", ""},
	} {
		h, ok := tb.Lookup(netip.MustParseAddr(c.ip))
		if got := map[bool]string{true: h.Country}[ok]; got != c.cc {
			t.Errorf("%s -> %q (ok %v), want %q", c.ip, h.Country, ok, c.cc)
		}
		if ok && h.Relay != "apple-private-relay" {
			t.Errorf("%s: relay %q", c.ip, h.Relay)
		}
	}
	var nilT *Table
	if _, ok := nilT.Lookup(netip.MustParseAddr("172.224.226.1")); ok {
		t.Error("a nil table matched")
	}
}

func TestIngest(t *testing.T) {
	defer Set(nil)
	Set(nil)
	dir := t.TempDir()
	many := map[string][]string{"JP": {"10.0.0.0/24", "10.0.2.0/24", "10.0.4.0/24", "10.0.6.0/24"}}
	if _, err := Ingest(dir, doc(t, "2026-10-13T00:00:00Z", many)); err != nil {
		t.Fatal(err)
	}
	if Current() == nil || Current().Prefixes != 4 {
		t.Fatalf("not installed: %+v", Current())
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Errorf("not written: %v", err)
	}
	// Older than the one in use: a replay.
	if _, err := Ingest(dir, doc(t, "2026-10-12T00:00:00Z", many)); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("an older document was taken: %v", err)
	}
	// Lost more than half its prefixes.
	if _, err := Ingest(dir, doc(t, "2026-10-14T00:00:00Z", map[string][]string{"JP": {"10.0.0.0/24"}})); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Errorf("a halved document was taken: %v", err)
	}
	// Another schema.
	if _, err := Ingest(dir, []byte(`{"schemaVersion":2,"relays":{}}`)); err == nil {
		t.Error("schemaVersion 2 was taken")
	}
	if Current().Prefixes != 4 {
		t.Error("a refused document replaced the one in use")
	}

	// A restart loads the copy kept in the dir.
	Set(nil)
	if err := LoadDir(dir); err != nil || Current() == nil || Current().Prefixes != 4 {
		t.Errorf("LoadDir: %v, %+v", err, Current())
	}
	Set(nil)
	if err := LoadDir(t.TempDir()); err != nil || Current() != nil {
		t.Errorf("an empty dir: %v, %+v", err, Current())
	}
}
