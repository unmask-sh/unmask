package ban

import "testing"

// The ban file is matched by string equality against $remote_addr, which
// nginx prints with inet_ntop: RFC 5952 text -- lower case, the longest run
// of zero groups as "::", a v4-mapped address as "::ffff:a.b.c.d".  Whatever
// spelling an operator types, or a proxy header carries, must come out in
// that one form; a prefix is masked to its network.  What is not an address
// is left as it was.
func TestNormalizeIPMatchesInetNtop(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.5", "203.0.113.5"},
		{" 203.0.113.5 ", "203.0.113.5"},
		{"2001:DB8::1", "2001:db8::1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"}, // the longest zero run, the leftmost on a tie
		{"2001:DB8:0:0:0:0:2:1", "2001:db8::2:1"},
		{"::FFFF:203.0.113.5", "::ffff:203.0.113.5"},
		{"::ffff:cb00:7105", "::ffff:203.0.113.5"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"2001:DB8:1:2:3:4:5:6/64", "2001:db8:1:2::/64"},
		{"203.0.113.77/24", "203.0.113.0/24"},
		{"", ""},
		{"not-an-address", "not-an-address"},
		{"001.002.003.004", "001.002.003.004"}, // leading zeros are not an address; left alone
		{"2001:db8::/129", "2001:db8::/129"},
	} {
		if got := normalizeIP(c.in); got != c.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPrefixKeys(t *testing.T) {
	p, ok := parsePrefixKey("2001:db8:1:2::/64")
	if !ok || p.String() != "2001:db8:1:2::/64" {
		t.Fatalf("parsePrefixKey = %v %v", p, ok)
	}
	if _, ok := parsePrefixKey("2001:db8::1"); ok {
		t.Error("a single address read as a prefix")
	}
	if _, ok := parsePrefixKey("x/64"); ok {
		t.Error("garbage read as a prefix")
	}
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"2001:db8:1:2::1", true},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", true},
		{"2001:db8:1:3::1", false},
		{"203.0.113.5", false},
		{"", false},
	} {
		if got := addrInPrefix(p, c.ip); got != c.want {
			t.Errorf("addrInPrefix(%s, %q) = %v, want %v", p, c.ip, got, c.want)
		}
	}
	v4, _ := parsePrefixKey("203.0.113.0/24")
	if !addrInPrefix(v4, "::ffff:203.0.113.9") {
		t.Error("a v4-mapped address is not seen in its IPv4 prefix")
	}
	if addrInPrefix(v4, "203.0.114.9") {
		t.Error("an address outside the prefix is seen in it")
	}
}
