package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAsnRenderBlocks pins the native ASN wiring: the action map + the
// is_net_challenge combining map are always defined, the final-challenge
// composite key routes on is_net_challenge, and enabled rules/providers emit
// their keyed action-map entries (exact "AS<n>" and org "org:<pattern>").
func TestAsnRenderBlocks(t *testing.T) {
	off := renderHTTPInc(t, nil)
	if !strings.Contains(off, "map $unmask_asn $unmask_asn_action") {
		t.Error("no rules: $unmask_asn_action map must still be defined")
	}
	if !strings.Contains(off, "map \"$geo_challenge_eff:$asn_challenge_eff:$unmask_cr_challenge\" $is_net_challenge") {
		t.Error("no rules: is_net_challenge combining map missing (must combine the per-axis effective verdicts)")
	}
	if !strings.Contains(off, "$is_net_challenge:$protected_mode") {
		t.Error("composite final-challenge key must route on is_net_challenge")
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Providers: []settings.AsnProviderSel{
				{ID: "microsoft", Action: settings.GeoActionDeny, Enabled: true},
				{ID: "google", Action: settings.GeoActionPoWOnly, Enabled: false}, // disabled -> omitted
			},
			Rules: []settings.AsnRule{
				{ASN: 16509, Action: settings.GeoActionCaptchaOnly, Enabled: true}, // exact
				{Org: "Hetzner", Action: settings.GeoActionDeny, Enabled: true},    // org
				{ASN: 99999, Action: settings.GeoActionDeny, Enabled: false},       // disabled
			},
		}
	})
	for _, want := range []string{
		`geo $remote_addr $unmask_asn {`,
		`"AS16509" "captcha_only";`, // exact custom rule
		`"org:hetzner" "deny";`,     // org custom rule (lower-cased key)
		`"org:microsoft" "deny";`,   // enabled provider (org pattern)
	} {
		if !strings.Contains(on, want) {
			t.Errorf("expected %q in http.inc", want)
		}
	}
	if strings.Contains(on, `"AS99999"`) {
		t.Error("disabled custom rule must not render")
	}
	if strings.Contains(on, `"org:google"`) {
		t.Error("disabled provider must not render")
	}
}

// asnMMDB returns an ASN mmdb the walk can read, or skips (present in dev,
// absent in bare CI; probe with a walk, since a path can exist unreadable).
func asnMMDB(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"/var/lib/unmask/ipgeo/dbip-asn.mmdb",
		"/usr/share/GeoIP/GeoLite2-ASN.mmdb",
	} {
		if body, err := ipgeo.CIDRsForASNTargets(p, []ipgeo.ASNTarget{{ASN: 63949, Value: "x"}}); err == nil && body != "" {
			return p
		}
	}
	t.Skip("no readable ASN mmdb available")
	return ""
}

// TestAsnRenderLinodeByNumber: the Linode provider renders as its AS number,
// ranked under the custom rules, and its old "Akamai" pattern -- which took in
// the networks Apple's iCloud Private Relay leaves from -- is gone.
func TestAsnRenderLinodeByNumber(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Providers:     []settings.AsnProviderSel{{ID: "linode", Action: settings.GeoActionDeny, Enabled: true}},
		}
	})
	if !strings.Contains(on, `"AS63949" "deny";`) {
		t.Error("the linode provider does not render its AS number")
	}
	if strings.Contains(on, `"org:akamai"`) {
		t.Error("the bare Akamai pattern still renders")
	}
}

// TestAsnWalkLinodeSparesRelay walks a real ASN mmdb: Linode's networks are
// in the geo block (keyed by the number or by the cloud's own name, whichever
// the database matches first), the relay's (AS36183) are not.
func TestAsnWalkLinodeSparesRelay(t *testing.T) {
	mmdb := asnMMDB(t)
	s := settings.Settings{}
	s.IPGeo.MMDBASNPath = mmdb
	s.Nginx.Asn = settings.AsnConfig{
		Providers: []settings.AsnProviderSel{{ID: "linode", Action: settings.GeoActionDeny, Enabled: true}},
	}
	d, err := buildRenderData(s, t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	cidrsOf := func(asn uint) []string {
		t.Helper()
		body, err := ipgeo.CIDRsForASNTargets(mmdb, []ipgeo.ASNTarget{{ASN: asn, Value: "x"}})
		if err != nil || body == "" {
			t.Fatalf("cannot list AS%d in %s: %v", asn, mmdb, err)
		}
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			out = append(out, strings.Fields(line)[0])
		}
		return out
	}
	for _, cidr := range cidrsOf(63949) {
		if !strings.Contains(d.AsnCIDRs, "    "+cidr+" ") {
			t.Errorf("Linode network %s is not in the geo block", cidr)
			break
		}
	}
	for _, cidr := range cidrsOf(36183) {
		if strings.Contains(d.AsnCIDRs, "    "+cidr+" ") {
			t.Errorf("relay network %s is in the linode provider's geo block", cidr)
			break
		}
	}
}
