package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cbTestMatcher builds a matcher holding one ip_only entry, through the real
// writer + loader so the test exercises the same path production does.
func cbTestMatcher(t *testing.T, ip string) *communitybans.Matcher {
	t.Helper()
	dir := t.TempDir()
	doc := communitybans.FeedDocument{Version: 2, Entries: []communitybans.FeedEntry{
		{Match: communitybans.MatchIPOnly, IP: ip, Promoted: true},
	}}
	if err := communitybans.WriteMapFiles(doc, dir); err != nil {
		t.Fatal(err)
	}
	m, err := communitybans.LoadMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func cbSettings(mode, action string) settings.Settings {
	var s settings.Settings
	s.CommunityBans.SubscribeMode = mode
	s.CommunityBans.Action = action
	return s
}

// The forward-auth wire must enforce the feed at the action the operator
// picked.  Before this axis existed an Apache / fa-nginx node pulled the feed,
// listed it in the UI and enforced none of it -- the subscription was
// decorative on exactly the deploy mode that cannot read the nginx maps.
func TestCommunityBansDecideHonoursTheAction(t *testing.T) {
	const listed = "203.0.113.9"
	m := cbTestMatcher(t, listed)

	for _, c := range []struct {
		name    string
		action  string
		wantSev axisSeverity
	}{
		{"default (unset) -> the chain", "", sevPoWThenCaptcha},
		{"pow_only", settings.RateChallengePoWOnly, sevPoWOnly},
		{"captcha_only", settings.RateChallengeCaptchaOnly, sevCaptchaOnly},
		{"pow_then_captcha", settings.RateChallengePoWThenCaptcha, sevPoWThenCaptcha},
		{"deny", settings.RateChallengeDeny, sevDeny},
		{"garbage falls back to the default", "not-a-mode", sevPoWThenCaptcha},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := cbSettings(settings.SubscribeFetchApply, c.action)
			d, ok := communityBansDecide(m, listed, "", cfg)
			if !ok {
				t.Fatal("a listed client produced no decision")
			}
			if d.sev != c.wantSev {
				t.Errorf("sev=%d, want %d", d.sev, c.wantSev)
			}
			if !strings.HasPrefix(d.reason, "community_bans:") {
				t.Errorf("reason=%q, want a community_bans: prefix", d.reason)
			}
			// A challenge decision must carry the chain to serve; a deny must not.
			wantCh := chModeFromSeverity(c.wantSev)
			if d.chMode != wantCh {
				t.Errorf("chMode=%q, want %q", d.chMode, wantCh)
			}
		})
	}
}

// Subscribing without applying (= browse the feed, enforce nothing) and being
// off entirely must both leave traffic alone, matching the native path: those
// modes write empty map files.
func TestCommunityBansDecideRespectsSubscribeMode(t *testing.T) {
	const listed = "203.0.113.9"
	m := cbTestMatcher(t, listed)

	for _, mode := range []string{"", settings.SubscribeOff, settings.SubscribeFetch} {
		cfg := cbSettings(mode, settings.RateChallengeDeny)
		if _, ok := communityBansDecide(m, listed, "", cfg); ok {
			t.Errorf("subscribe_mode=%q enforced the feed", mode)
		}
	}
	cfg := cbSettings(settings.SubscribeFetchApply, "")
	if _, ok := communityBansDecide(m, "192.0.2.1", "", cfg); ok {
		t.Error("an unlisted client produced a decision")
	}
	if _, ok := communityBansDecide(nil, listed, "", cfg); ok {
		t.Error("a nil matcher (= no client wired) enforced something")
	}
}

// Both wires resolve the SAME action from the SAME setting.  The native path
// cannot call communityBansDecide -- nginx decides inline from a rendered
// constant -- so this pins the two derivations against each other for every
// action, which is the whole point of the redesign: the previous native wiring
// hardcoded "captcha" and forward-auth did nothing at all.
func TestCommunityBansBothWiresAgreeOnTheAction(t *testing.T) {
	const listed = "203.0.113.9"
	m := cbTestMatcher(t, listed)

	for _, action := range []string{
		"", settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly,
		settings.RateChallengePoWThenCaptcha, settings.RateChallengeDeny,
	} {
		cfg := cbSettings(settings.SubscribeFetchApply, action)
		resolved := cfg.CommunityBans.ResolvedAction()

		// Wire 1: forward-auth.
		d, ok := communityBansDecide(m, listed, "", cfg)
		if !ok {
			t.Fatalf("action=%q: forward-auth did not enforce", action)
		}
		faDenies := d.sev == sevDeny
		faNeedsCaptcha := d.chMode == settings.RateChallengeCaptchaOnly ||
			d.chMode == settings.RateChallengePoWThenCaptcha

		// Wire 2: what render.go bakes into the nginx conf.
		nativeDenies := resolved == settings.RateChallengeDeny
		nativeNeedsCaptcha := !nativeDenies &&
			(resolved == settings.RateChallengeCaptchaOnly || resolved == settings.RateChallengePoWThenCaptcha)

		if faDenies != nativeDenies {
			t.Errorf("action=%q: forward-auth denies=%v, native denies=%v", action, faDenies, nativeDenies)
		}
		if faNeedsCaptcha != nativeNeedsCaptcha {
			t.Errorf("action=%q: forward-auth requires a CAPTCHA-grade pass=%v, native=%v",
				action, faNeedsCaptcha, nativeNeedsCaptcha)
		}
	}
}
