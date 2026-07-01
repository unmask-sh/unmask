package ipgeo

import "testing"

// TestOpenOverrideASN covers the test-only UNMASK_TEST_GEO_OVERRIDE 3-field
// form (<ip>:<country>:<asn>): the ASN is seeded into Info.ASN and any entry
// carrying an ASN flips ASNLoaded() on, so the e2e harness can exercise the
// roaming ASN veto without a real ASN mmdb.
func TestOpenOverrideASN(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "192.0.2.91:JP:64500, 192.0.2.92:JP:64501 ,192.0.2.93:JP")
	r := Open("", "")
	defer r.Close()

	if !r.Loaded() {
		t.Fatal("override should mark the geo reader loaded")
	}
	if !r.ASNLoaded() {
		t.Fatal("an override carrying an ASN should report ASNLoaded() = true")
	}
	for _, c := range []struct {
		ip  string
		cc  string
		asn uint
	}{
		{"192.0.2.91", "JP", 64500},
		{"192.0.2.92", "JP", 64501},
		{"192.0.2.93", "JP", 0}, // no ASN field -> ASN stays 0
	} {
		got := r.LookupInfo(c.ip)
		if got.Country != c.cc || got.ASN != c.asn {
			t.Errorf("LookupInfo(%s) = {Country:%q ASN:%d}, want {Country:%q ASN:%d}",
				c.ip, got.Country, got.ASN, c.cc, c.asn)
		}
	}
}

// TestOpenOverrideNoASN guards the back-compat path: a 2-field override (no
// ASN anywhere) must NOT flip ASNLoaded(), so existing scenarios keep the veto
// auto-skipped exactly as before.
func TestOpenOverrideNoASN(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "192.0.2.81:JP,192.0.2.82:CN,192.0.2.83:US")
	r := Open("", "")
	defer r.Close()

	if r.ASNLoaded() {
		t.Fatal("overrides without any ASN must NOT flip ASNLoaded()")
	}
	if got := r.LookupInfo("192.0.2.82"); got.Country != "CN" {
		t.Errorf("LookupInfo(192.0.2.82).Country = %q, want CN", got.Country)
	}
	if got := r.LookupInfo("192.0.2.82"); got.ASN != 0 {
		t.Errorf("LookupInfo(192.0.2.82).ASN = %d, want 0", got.ASN)
	}
}
