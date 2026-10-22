package nginxconf

import (
	"errors"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// stubPreviewWalk replaces the ASN walk for one test and records the targets
// it was asked for.
func stubPreviewWalk(t *testing.T, cidrs string, err error) *[]ipgeo.ASNTarget {
	t.Helper()
	var got []ipgeo.ASNTarget
	prev := previewWalk
	previewWalk = func(path string, targets []ipgeo.ASNTarget) (string, error) {
		got = append(got, targets...)
		return cidrs, err
	}
	t.Cleanup(func() { previewWalk = prev })
	return &got
}

// withCountryRule: an install where the country axis can fire -- the world is
// challenged, one country denied -- and an ASN mmdb is configured.
func withCountryRule(s *settings.Settings) {
	s.IPGeo.MMDBASNPath = "/nonexistent/asn.mmdb"
	s.Nginx.Geo.DefaultAction = settings.RateChallengePoWThenCaptcha
	s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true}}
}

// Every fetcher the pair verifies is an upstream pattern of the social-preview
// group, byte for byte: the UA map is keyed on the upstream pattern, and a
// pattern that drifted would verify nothing without anyone noticing.
func TestPreviewFetchersAreUpstreamSocialPreviewPatterns(t *testing.T) {
	social := map[string]bool{}
	for _, e := range classify.UpstreamRescueList()["social-preview"] {
		social[e.Pattern] = true
	}
	for _, f := range PreviewFetchers {
		if !social[f.Pattern] {
			t.Errorf("%q is not a social-preview pattern of the upstream snapshot", f.Pattern)
		}
		if len(f.ASNs) == 0 || f.Token == "" {
			t.Errorf("%q: a fetcher needs a token and a network", f.Pattern)
		}
	}
}

// With a country rule and an ASN mmdb, the three maps are drawn from the walk,
// and the pair reaches every place the two axes act.
func TestPreviewVerifyRender(t *testing.T) {
	got := stubPreviewWalk(t, "199.16.156.0/22 \"AS13414\";\n157.240.0.0/16 \"AS32934\";\n147.92.128.0/17 \"AS38631\";\n", nil)
	httpInc, _, _ := renderIncs(t, withCountryRule)
	for _, want := range []string{
		// the vendors' networks, as the walk wrote them
		"geo $remote_addr $unmask_preview_asn {",
		`199.16.156.0/22 "AS13414";`,
		`147.92.128.0/17 "AS38631";`,
		// the fetchers' names, Facebook's first
		"map $http_user_agent $unmask_preview_ua {\n    default \"\";\n    \"~*facebookexternalhit\" \"fbexthit\";\n    \"~*Facebot\" \"facebot\";\n    \"~*Twitterbot\" \"twitterbot\";\n}",
		// the pairs
		`"fbexthit:AS32934" 1;`,
		`"fbexthit:AS38631" 1;`,
		`"facebot:AS32934" 1;`,
		`"twitterbot:AS13414" 1;`,
		// what the axes read: challenge, deny, CAPTCHA grade
		`map "$is_geo_exempt_path$unmask_preview_verified" $unmask_geo_exempt {`,
		`map "$is_asn_exempt_path$unmask_preview_verified" $unmask_asn_exempt {`,
		`map "$is_geo_challenge:$unmask_geo_exempt" $geo_challenge_eff {`,
		`map "$is_asn_challenge:$unmask_asn_exempt" $asn_challenge_eff {`,
		`map "$unmask_geo_exempt:$unmask_geo_action" $geo_deny_eff {`,
		`map "$unmask_asn_exempt:$unmask_asn_action" $asn_deny_eff {`,
		`map "$unmask_geo_exempt:$unmask_geo_action" $unmask_geo_captcha {`,
		`map "$unmask_asn_exempt:$unmask_asn_action" $unmask_asn_captcha {`,
		// not on the name alone: no name-only budget
		`map "$is_search_bot:$bv_any_valid:$is_bypass_ip:$is_bypass_path:$unmask_preview_verified" $unmask_named_rate_key {`,
		`"1:0:0:0:0"`,
		// the access log says so
		" pv=$unmask_preview_verified sb=$is_search_bot ua=$http_user_agent'",
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	if strings.Contains(httpInc, `map "" $unmask_preview_verified { default 0; }`) {
		t.Error("the constant stands in for the live map")
	}
	// The walk was asked for the three networks once each, in order.
	var asns []uint
	for _, tg := range *got {
		asns = append(asns, tg.ASN)
		if tg.Value != "AS"+strings.TrimPrefix(tg.Value, "AS") || tg.OrgPattern != "" || tg.InOrder {
			t.Errorf("target %+v: want an exact AS number valued AS<n>", tg)
		}
	}
	if want := []uint{13414, 32934, 38631}; len(asns) != len(want) || asns[0] != want[0] || asns[1] != want[1] || asns[2] != want[2] {
		t.Errorf("walk targets = %v, want %v", asns, want)
	}
	// The rest of the name-only contract is untouched.
	for _, want := range []string{
		`"~^0:1:0:0:0:1:"                  1;`, // a named crawler under a country / network / custom rule
		`(?:GET|HEAD)$`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
}

// The check is inert -- the variable a constant, the walk unpaid -- without an
// ASN mmdb, without an axis that can fire, and when the walk comes back empty
// or broken.
func TestPreviewVerifyInert(t *testing.T) {
	cases := map[string]struct {
		mutate func(*settings.Settings)
		cidrs  string
		err    error
	}{
		"no ASN mmdb": {mutate: func(s *settings.Settings) {
			withCountryRule(s)
			s.IPGeo.MMDBASNPath = ""
		}, cidrs: "1.2.3.0/24 \"AS13414\";\n"},
		"no axis can fire": {mutate: func(s *settings.Settings) {
			s.IPGeo.MMDBASNPath = "/nonexistent/asn.mmdb"
			s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "JP", Action: settings.GeoActionSkip, Enabled: true}}
		}, cidrs: "1.2.3.0/24 \"AS13414\";\n"},
		"empty walk":  {mutate: withCountryRule, cidrs: ""},
		"broken walk": {mutate: withCountryRule, cidrs: "1.2.3.0/24 \"AS13414\";\n", err: errors.New("open: no such file")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := stubPreviewWalk(t, tc.cidrs, tc.err)
			httpInc, _, _ := renderIncs(t, tc.mutate)
			if !strings.Contains(httpInc, `map "" $unmask_preview_verified { default 0; }`) {
				t.Error("http.inc lacks the constant")
			}
			if strings.Contains(httpInc, "$unmask_preview_asn") || strings.Contains(httpInc, "$unmask_preview_ua") {
				t.Error("http.inc draws the live maps")
			}
			walked := len(*got) > 0
			if wantWalk := name == "empty walk" || name == "broken walk"; walked != wantWalk {
				t.Errorf("walked = %v, want %v", walked, wantWalk)
			}
			// The axes still read the exempt variables, so the conf is one shape.
			if !strings.Contains(httpInc, `map "$is_geo_challenge:$unmask_geo_exempt" $geo_challenge_eff {`) {
				t.Error("http.inc lacks the geo exempt composite")
			}
		})
	}
}

// A fetcher the operator judges -- set to normal checks or stopped on the UA
// filter -- is not verified: the pair clears an axis only for a crawler the
// operator passes.
func TestPreviewVerifyFollowsUAFilter(t *testing.T) {
	stubPreviewWalk(t, "199.16.156.0/22 \"AS13414\";\n", nil)
	httpInc, _, _ := renderIncs(t, func(s *settings.Settings) {
		withCountryRule(s)
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{`Twitterbot`: classify.GroupModeBlack}
	})
	if strings.Contains(httpInc, `"~*Twitterbot" "twitterbot";`) || strings.Contains(httpInc, `"twitterbot:AS13414" 1;`) {
		t.Error("a stopped fetcher is verified")
	}
	if !strings.Contains(httpInc, `"~*facebookexternalhit" "fbexthit";`) {
		t.Error("the other fetchers lost their entry")
	}
	// The whole group stopped: nothing to verify, the walk is not paid for.
	got := stubPreviewWalk(t, "199.16.156.0/22 \"AS13414\";\n", nil)
	httpInc, _, _ = renderIncs(t, func(s *settings.Settings) {
		withCountryRule(s)
		s.Nginx.SearchBots.UpstreamGroupMode = map[string]string{"social-preview": classify.GroupModeNone}
	})
	if !strings.Contains(httpInc, `map "" $unmask_preview_verified { default 0; }`) || len(*got) > 0 {
		t.Error("a group under normal checks still verifies, or paid for a walk")
	}
}
