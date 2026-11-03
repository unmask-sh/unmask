package ipgeo

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// A MaxMind DB file written by hand, so the tests can open a real reader
// without a fixture from a vendor: an IPv4 search tree of 24-bit records, a
// data section, and the metadata map the reader requires.  Only the subset
// of the format the tests use is written (maps, strings, unsigned integers,
// one array); the reader decodes it like any other file.

// mmdbEntry maps an IPv4 prefix to one encoded data record.
type mmdbEntry struct {
	prefix netip.Prefix
	data   []byte
}

func mmdbString(s string) []byte {
	if len(s) < 29 {
		return append([]byte{0x40 | byte(len(s))}, s...)
	}
	return append([]byte{0x40 | 29, byte(len(s) - 29)}, s...)
}

func mmdbUint16(v uint16) []byte { return []byte{0xA0 | 2, byte(v >> 8), byte(v)} }

func mmdbUint32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append([]byte{0xC0 | 4}, b[:]...)
}

func mmdbUint64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append([]byte{0x00 | 8, 9 - 7}, b[:]...)
}

// mmdbMap encodes a map from alternating key (string) and encoded value.
func mmdbMap(kv ...any) []byte {
	out := []byte{0xE0 | byte(len(kv)/2)}
	for i := 0; i < len(kv); i += 2 {
		out = append(out, mmdbString(kv[i].(string))...)
		out = append(out, kv[i+1].([]byte)...)
	}
	return out
}

func mmdbArray(items ...[]byte) []byte {
	out := []byte{0x00 | byte(len(items)), 11 - 7}
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// countryRecord is what a Country database says for an address.
func countryRecord(iso, name string) []byte {
	return mmdbMap("country", mmdbMap("iso_code", mmdbString(iso), "names", mmdbMap("en", mmdbString(name))))
}

// asnRecord is what an ASN database says for an address.
func asnRecord(asn uint32, org string) []byte {
	return mmdbMap("autonomous_system_number", mmdbUint32(asn), "autonomous_system_organization", mmdbString(org))
}

// writeTestMMDB writes an IPv4 database of the entries to a file in t's
// temporary directory and returns its path.  Prefixes must not overlap.
func writeTestMMDB(t *testing.T, dbType string, entries []mmdbEntry) string {
	t.Helper()
	type record struct {
		kind int // 0 empty, 1 node, 2 data
		idx  int // node index, or data offset
	}
	nodes := [][2]record{{}}
	var data []byte
	for _, e := range entries {
		off := len(data)
		data = append(data, e.data...)
		addr := e.prefix.Addr().As4()
		bits := e.prefix.Bits()
		node := 0
		for i := 0; i < bits; i++ {
			bit := (addr[i/8] >> (7 - uint(i%8))) & 1
			if i == bits-1 {
				nodes[node][bit] = record{kind: 2, idx: off}
				break
			}
			if nodes[node][bit].kind == 0 {
				nodes = append(nodes, [2]record{})
				nodes[node][bit] = record{kind: 1, idx: len(nodes) - 1}
			}
			node = nodes[node][bit].idx
		}
	}
	count := len(nodes)
	value := func(r record) uint32 {
		switch r.kind {
		case 1:
			return uint32(r.idx)
		case 2:
			return uint32(count + 16 + r.idx)
		}
		return uint32(count)
	}
	var file []byte
	for _, n := range nodes {
		for _, r := range n {
			v := value(r)
			file = append(file, byte(v>>16), byte(v>>8), byte(v))
		}
	}
	file = append(file, make([]byte, 16)...)
	file = append(file, data...)
	file = append(file, "\xAB\xCD\xEFMaxMind.com"...)
	file = append(file, mmdbMap(
		"binary_format_major_version", mmdbUint16(2),
		"binary_format_minor_version", mmdbUint16(0),
		"build_epoch", mmdbUint64(1700000000),
		"database_type", mmdbString(dbType),
		"description", mmdbMap("en", mmdbString("test database")),
		"ip_version", mmdbUint16(4),
		"languages", mmdbArray(mmdbString("en")),
		"node_count", mmdbUint32(uint32(count)),
		"record_size", mmdbUint16(24),
	)...)
	path := filepath.Join(t.TempDir(), dbType+".mmdb")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testCountryDB: a Country database placing 203.0.113.0/24 in JP and
// 198.51.100.0/24 in US.
func testCountryDB(t *testing.T) string {
	t.Helper()
	return writeTestMMDB(t, "Test-Country", []mmdbEntry{
		{netip.MustParsePrefix("203.0.113.0/24"), countryRecord("JP", "Japan")},
		{netip.MustParsePrefix("198.51.100.0/24"), countryRecord("US", "United States")},
	})
}

// testASNDB: an ASN database placing 203.0.113.0/24 in AS64500.
func testASNDB(t *testing.T) string {
	t.Helper()
	return writeTestMMDB(t, "Test-ASN", []mmdbEntry{
		{netip.MustParsePrefix("203.0.113.0/24"), asnRecord(64500, "Example Network")},
	})
}

// TestWriteTestMMDB pins the hand-written file against the reader: the
// fixture every other test here opens must say what it was given.
func TestWriteTestMMDB(t *testing.T) {
	r := Open(testCountryDB(t), testASNDB(t))
	defer r.Close()
	if !r.Loaded() || !r.ASNLoaded() {
		t.Fatalf("loaded=%v asn=%v, want both", r.Loaded(), r.ASNLoaded())
	}
	got := r.LookupInfo("203.0.113.7")
	if got.Country != "JP" || got.CountryName != "Japan" || got.ASN != 64500 || got.ASNOrg != "Example Network" {
		t.Fatalf("203.0.113.7: %+v", got)
	}
	if got := r.LookupInfo("198.51.100.200"); got.Country != "US" || got.ASN != 0 {
		t.Fatalf("198.51.100.200: %+v", got)
	}
	if got := r.LookupInfo("192.0.2.1"); got.Country != "" || got.ASN != 0 {
		t.Fatalf("192.0.2.1 (unlisted): %+v", got)
	}
	if asn, org := r.LookupASN("203.0.113.9"); asn != 64500 || org != "Example Network" {
		t.Fatalf("LookupASN: %d %q", asn, org)
	}
}
