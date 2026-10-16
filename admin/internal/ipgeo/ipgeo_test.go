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

// TestLocalAddresses: an address off the public Internet is Local, decided
// from the address alone -- with no database, and ahead of the relay list
// and the override table -- while a public address the database cannot
// place stays "", so the admin tells the two apart.
func TestLocalAddresses(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "192.0.2.91:JP")
	r := Open("", "")
	defer r.Close()
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.10.10", "100.64.0.1", "100.127.255.254", "0.0.0.0",
		"::1", "fd12::1", "fe80::1", "::", "::ffff:192.168.0.1"} {
		if !IsLocal(ip) {
			t.Errorf("IsLocal(%s) = false", ip)
		}
		if got := r.LookupInfo(ip); got.Country != Local || got.CountryName != "Local network" {
			t.Errorf("LookupInfo(%s) = %+v, want Local", ip, got)
		}
		if got := (*Reader)(nil).Lookup(ip); got != Local {
			t.Errorf("a nil reader: Lookup(%s) = %q, want Local", ip, got)
		}
	}
	for _, ip := range []string{"192.0.2.1", "100.128.0.1", "172.32.0.1", "2001:db8::1", "8.8.8.8", "not an address", ""} {
		if IsLocal(ip) {
			t.Errorf("IsLocal(%s) = true", ip)
		}
	}
	if got := r.Lookup("192.0.2.1"); got != "" {
		t.Errorf("a public address outside the data: Lookup = %q, want \"\"", got)
	}
	if got := r.Lookup("192.0.2.91"); got != "JP" {
		t.Errorf("the override: Lookup = %q, want JP", got)
	}
	if got := CountryName(Local); got != "Local network (ローカル)" {
		t.Errorf("CountryName(Local) = %q", got)
	}
	if _, listed := Countries[Local]; listed {
		t.Error("Local must stay out of the country master list (a rule on it matches nothing)")
	}
}
