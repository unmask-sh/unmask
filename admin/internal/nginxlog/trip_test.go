package nginxlog

import "testing"

// A honeypot trip bans its client only when nothing says a page caused it.
func TestTripBannable(t *testing.T) {
	cases := []struct {
		sfs, sfd, rh string
		want         bool
		why          string
	}{
		{"", "", "", true, "a scanner sends none of the headers"},
		{"none", "document", "", true, "a URL typed into a browser"},
		{"none", "empty", "", true, "a fetch from a script on no page"},
		{"cross-site", "image", "", false, "an <img> on a third party's page"},
		{"cross-site", "document", "", false, "a link clicked on another site"},
		{"same-origin", "document", "", false, "a link in a post on this site"},
		{"same-site", "iframe", "", false, "a frame on a sibling host"},
		{"none", "image", "", false, "a subresource whatever its site"},
		{"", "", "attacker.example", false, "a Referer, with no Sec-Fetch at all"},
		{"", "script", "", false, "a <script src> from an old browser"},
	}
	for _, c := range cases {
		if got := TripBannable(c.sfs, c.sfd, c.rh); got != c.want {
			t.Errorf("TripBannable(%q, %q, %q) = %v, want %v (%s)", c.sfs, c.sfd, c.rh, got, c.want, c.why)
		}
	}
}

// The three fields parse from a line that carries them, and a line from a
// configuration that predates them still parses with them empty.
func TestParseTripFields(t *testing.T) {
	r := &Reader{}
	p, ok := r.parse("1700000000.123 site=example.com kind= fc=0 hp=1 ip=203.0.113.9 ja4=t13d1516h2_8daaf6152771_b0da82dd1658 hpuri=/?q=%27 bp=0 scheme=https cr=- pv=0 sb=0 sfs=cross-site sfd=image rh=attacker.example ua=Mozilla/5.0 (X11) Gecko")
	if !ok {
		t.Fatal("line with the trip fields did not parse")
	}
	if p.sfs != "cross-site" || p.sfd != "image" || p.rh != "attacker.example" || p.ua != "Mozilla/5.0 (X11) Gecko" {
		t.Errorf("fields: sfs=%q sfd=%q rh=%q ua=%q", p.sfs, p.sfd, p.rh, p.ua)
	}
	if r.honeypotBanAllowed(p) {
		t.Error("a cross-site image trip was allowed to ban")
	}
	old, ok := r.parse("1700000000.123 site=example.com kind= fc=0 hp=1 ip=203.0.113.9 ja4=- hpuri=/?q=%27 bp=0 scheme=https cr=- pv=0 sb=0 ua=curl/8.0")
	if !ok {
		t.Fatal("line without the trip fields did not parse")
	}
	if old.sfs != "" || old.sfd != "" || old.rh != "" || old.ua != "curl/8.0" {
		t.Errorf("old line: sfs=%q sfd=%q rh=%q ua=%q", old.sfs, old.sfd, old.rh, old.ua)
	}
	if !r.honeypotBanAllowed(old) {
		t.Error("a bare scanner trip was not allowed to ban")
	}
}

// A rescued crawler name is exempt from the honeypot ban, unless the name is
// one the configuration verifies against a vendor range and this request was
// not passed on that range.
func TestHoneypotBanSearchBotRange(t *testing.T) {
	r := &Reader{}
	r.SetSearchBotCheck(func(ua string) bool { return ua == "Googlebot" || ua == "SomeFeedReader" })
	r.SetRangeVerifiedCheck(func(ua string) bool { return ua == "Googlebot" })
	line := func(ua string, bp string) parsed {
		p, ok := r.parse("1700000000.123 site=example.com kind= fc=0 hp=1 ip=203.0.113.9 ja4=- hpuri=/?q=%27 bp=" + bp + " scheme=https cr=- pv=0 sb=0 ua=" + ua)
		if !ok {
			t.Fatalf("line for %q did not parse", ua)
		}
		return p
	}
	if r.honeypotBanAllowed(line("Googlebot", "1")) {
		t.Error("a range-passed Googlebot was allowed to ban")
	}
	if !r.honeypotBanAllowed(line("Googlebot", "0")) {
		t.Error("a Googlebot name from outside the range kept its exemption")
	}
	if r.honeypotBanAllowed(line("SomeFeedReader", "0")) {
		t.Error("a name without a vendor range lost its exemption")
	}
}
