package ipgeo

import (
	"reflect"
	"testing"
)

// testIndex builds a small hand-made index (no mmdb needed) so the search logic
// is tested deterministically.
func testIndex() *asnSuggestIndex {
	orgs := []asnOrgEntry{
		{org: "Microsoft Corporation", asns: []uint{8075, 8068}, size24: 300000},
		{org: "Microsoft Limited", asns: []uint{200}, size24: 2},
		{org: "OVH SAS", asns: []uint{16276}, size24: 18000},
		{org: "Amazon.com, Inc.", asns: []uint{16509, 14618}, size24: 600000},
	}
	for i := range orgs {
		orgs[i].orgLow = toLower(orgs[i].org)
	}
	x := &asnSuggestIndex{orgs: orgs, byASN: map[uint]asnLoc{
		8075: {0, 200000}, 8068: {0, 100000}, 200: {1, 2},
		16276: {2, 18000}, 16509: {3, 400000}, 14618: {3, 200000},
	}}
	x.asnNums = []uint{200, 8068, 8075, 14618, 16276, 16509}
	return x
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// TestSuggestOrg: a text query returns matching orgs ranked by IPv4 size, each
// carrying its member AS numbers.
func TestSuggestOrg(t *testing.T) {
	x := testIndex()
	got := x.search("microsoft", 10)
	if len(got) != 2 {
		t.Fatalf("want 2 org hits, got %d (%+v)", len(got), got)
	}
	// Bigger org first.
	if got[0].Kind != "org" || got[0].Org != "Microsoft Corporation" || got[0].Value != "Microsoft Corporation" {
		t.Errorf("hit0 = %+v", got[0])
	}
	if !reflect.DeepEqual(got[0].ASNs, []uint{8075, 8068}) {
		t.Errorf("hit0 ASNs = %v, want [8075 8068]", got[0].ASNs)
	}
	if got[0].Size24 != 300000 {
		t.Errorf("hit0 Size24 = %d", got[0].Size24)
	}
	if got[1].Org != "Microsoft Limited" {
		t.Errorf("hit1 = %+v", got[1])
	}
}

// TestSuggestOrgCaseInsensitive: matching ignores case.
func TestSuggestOrgCaseInsensitive(t *testing.T) {
	x := testIndex()
	if got := x.search("OVH", 10); len(got) != 1 || got[0].Org != "OVH SAS" {
		t.Errorf("OVH search = %+v", got)
	}
}

// TestSuggestNumberExact: a bare number pinpoints the exact AS -> its org.
func TestSuggestNumberExact(t *testing.T) {
	x := testIndex()
	for _, q := range []string{"16509", "AS16509", "as16509"} {
		got := x.search(q, 10)
		if len(got) == 0 || got[0].Kind != "asn" || got[0].ASN != 16509 {
			t.Fatalf("%q -> %+v", q, got)
		}
		if got[0].Value != "AS16509" || got[0].Org != "Amazon.com, Inc." {
			t.Errorf("%q -> %+v", q, got[0])
		}
	}
}

// TestSuggestNumberPrefix: a short numeric fragment surfaces prefix matches,
// ascending, after any exact hit.
func TestSuggestNumberPrefix(t *testing.T) {
	x := testIndex()
	got := x.search("16", 10) // matches 16276, 16509 (both start "16")
	var nums []uint
	for _, s := range got {
		if s.Kind != "asn" {
			t.Fatalf("want asn kind, got %+v", s)
		}
		nums = append(nums, s.ASN)
	}
	if !reflect.DeepEqual(nums, []uint{16276, 16509}) {
		t.Errorf("prefix 16 -> %v, want [16276 16509]", nums)
	}
}

// TestSuggestNumberExactThenPrefix: exact match leads, prefix siblings follow.
func TestSuggestNumberExactThenPrefix(t *testing.T) {
	x := &asnSuggestIndex{
		orgs:  []asnOrgEntry{{org: "A", orgLow: "a", asns: []uint{16, 165, 1650}, size24: 9}},
		byASN: map[uint]asnLoc{16: {0, 3}, 165: {0, 3}, 1650: {0, 3}},
	}
	x.asnNums = []uint{16, 165, 1650}
	got := x.search("165", 10)
	if len(got) != 2 { // 165 exact + 1650 prefix (16 doesn't start with "165")
		t.Fatalf("want 2, got %d (%+v)", len(got), got)
	}
	if got[0].ASN != 165 { // exact first
		t.Errorf("exact should lead: %+v", got)
	}
	if got[1].ASN != 1650 {
		t.Errorf("prefix follows: %+v", got)
	}
}

// TestSuggestElision: an org with many ASNs caps the shown list and reports the
// remainder via ASNMore.
func TestSuggestElision(t *testing.T) {
	many := make([]uint, 0, 12)
	for i := 0; i < 12; i++ {
		many = append(many, uint(100+i))
	}
	x := &asnSuggestIndex{
		orgs:  []asnOrgEntry{{org: "BigCloud", orgLow: "bigcloud", asns: many, size24: 1}},
		byASN: map[uint]asnLoc{},
	}
	got := x.search("bigcloud", 10)
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if len(got[0].ASNs) != maxOrgASNs {
		t.Errorf("shown ASNs = %d, want %d", len(got[0].ASNs), maxOrgASNs)
	}
	if got[0].ASNMore != 12-maxOrgASNs {
		t.Errorf("ASNMore = %d, want %d", got[0].ASNMore, 12-maxOrgASNs)
	}
}

// TestSuggestNoMatch: a fragment matching nothing returns empty, not nil-panic.
func TestSuggestNoMatch(t *testing.T) {
	x := testIndex()
	if got := x.search("zzzznotfound", 10); len(got) != 0 {
		t.Errorf("want empty, got %+v", got)
	}
	if got := x.search("999999", 10); len(got) != 0 {
		t.Errorf("want empty for unknown AS, got %+v", got)
	}
}
