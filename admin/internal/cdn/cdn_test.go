package cdn

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func doc(generated string, cdns map[string]Entry) []byte {
	var b strings.Builder
	b.WriteString(`{"schemaVersion":1,"generatedAt":"` + generated + `","cdns":{`)
	first := true
	for id, e := range cdns {
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`"` + id + `":{"name":"` + e.Name + `","source":"x","ranges":[`)
		for i, r := range e.Ranges {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`"` + r + `"`)
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

// The built-in snapshot carries the three vendors, and a CloudFront
// origin-facing address is found in it; an address of nobody's is not.
func TestSnapshotAndLookup(t *testing.T) {
	s := Snapshot()
	if !s.Snapshot || s.Vendors != 3 || s.Prefixes < 100 {
		t.Fatalf("snapshot: vendors=%d prefixes=%d snapshot=%v", s.Vendors, s.Prefixes, s.Snapshot)
	}
	for _, id := range []string{"cloudfront", "cloudflare", "fastly"} {
		if len(s.Ranges(id)) == 0 {
			t.Errorf("snapshot lacks %s", id)
		}
	}
	// 130.176.88.0/21 is in the CloudFront origin-facing list the snapshot
	// was built from.
	if h, ok := s.Lookup(netip.MustParseAddr("130.176.88.7")); !ok || h.CDN != "cloudfront" {
		t.Errorf("130.176.88.7: %+v %v, want cloudfront", h, ok)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.5")); ok {
		t.Error("203.0.113.5 is nobody's egress")
	}
	if ids := s.VendorIDs(); len(ids) != 3 || ids[0] != "cloudflare" {
		t.Errorf("vendor ids: %v", ids)
	}
}

// Match reads the active table and the operator's own ranges; a mapped
// IPv4 address and an IPv6 one are looked up in their own families.
func TestMatch(t *testing.T) {
	Set(nil)
	t.Cleanup(func() { Set(nil) })
	tb, err := Parse(doc("2026-10-24T00:00:00Z", map[string]Entry{
		"cloudfront": {Name: "CF", Ranges: []string{"198.51.100.0/24", "2001:db8:1::/48"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	Set(tb)
	extra := ParsePrefixes([]string{"203.0.113.0/24", "2001:db8:2::1", "not a prefix"})
	if len(extra) != 2 {
		t.Fatalf("extra: %v", extra)
	}
	cases := map[string]string{
		"198.51.100.9":           "cloudfront",
		"::ffff:198.51.100.9":    "cloudfront",
		"2001:db8:1::9":          "cloudfront",
		"203.0.113.9":            Custom,
		"2001:db8:2::1":          Custom,
		"2001:db8:2::2":          "",
		"192.0.2.1":              "",
		"":                       "",
		"not an address at all!": "",
	}
	for ip, want := range cases {
		got, ok := Match(ip, extra)
		if got != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q %v, want %q", ip, got, ok, want)
		}
	}
}

// A hub document replaces the snapshot; an older one, or one that lost
// half its prefixes, is refused and the list in use stays.
func TestIngestGuards(t *testing.T) {
	Set(nil)
	t.Cleanup(func() { Set(nil) })
	dir := t.TempDir()
	newer := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	many := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		many = append(many, "10."+itoa(i)+".0.0/16")
	}
	tb, err := Ingest(dir, doc(newer, map[string]Entry{"cloudfront": {Name: "CF", Ranges: many}}))
	if err != nil {
		t.Fatalf("a newer, full document must go in: %v", err)
	}
	if Current() != tb || Active() != tb || tb.Snapshot {
		t.Error("the ingested document must be the active one")
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Errorf("the document is not kept in the sync dir: %v", err)
	}
	if _, err := Ingest(dir, doc("2020-01-01T00:00:00Z", map[string]Entry{"cloudfront": {Name: "CF", Ranges: many}})); err == nil {
		t.Error("an older document must be refused")
	}
	if _, err := Ingest(dir, doc(newer, map[string]Entry{"cloudfront": {Name: "CF", Ranges: many[:10]}})); err == nil {
		t.Error("a document that lost most prefixes must be refused")
	}
	if Active() != tb {
		t.Error("a refused document must not replace the one in use")
	}
	// A document older than the built-in snapshot is refused even with
	// nothing loaded: the snapshot is what is in use.
	Set(nil)
	if _, err := Ingest(dir, doc("2020-01-01T00:00:00Z", map[string]Entry{"cloudfront": {Name: "CF", Ranges: many}})); err == nil {
		t.Error("a document older than the snapshot must be refused")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
