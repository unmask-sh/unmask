package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// MatchPassEntry names the entry of a _bv value that verifies for the client
// the way the plugin verified it -- and nothing for another address, another
// host or no cookie.  The access-log reader keys its per-address count of
// distinct passes by the name.
func TestMatchPassEntryNamesTheVerifiedEntry(t *testing.T) {
	const secret, host, addr = "test-secret", "example.com", "203.0.113.5"
	h := newRebindTestHandler(t)
	h.SetSettings(settings.Settings{
		Secret:    settings.Secret{BVSecret: secret},
		Challenge: settings.ChallengeConfig{Default: settings.ChallengeValues{PowDifficulty: bvjTestDifficulty}},
	})
	pow := powPass(t, secret, addr, host)
	captcha := cookies.IssueValue(secret, addr, host, "captcha")

	if got := h.MatchPassEntry(pow, addr, host); got != pow {
		t.Errorf("a proof-of-work entry alone: %q, want the entry", got)
	}
	// Junk around the entry names the entry, not the junk.
	if got := h.MatchPassEntry("1785943030.pow2.zzzz.0~"+pow+"~garbage", addr, host); got != pow {
		t.Errorf("a padded value: %q, want the entry that verifies", got)
	}
	if got := h.MatchPassEntry(captcha, addr, host); got != captcha {
		t.Errorf("a CAPTCHA entry: %q, want the entry", got)
	}
	// A roaming list: the entry for this address, whichever position.
	other := cookies.IssueValue(secret, "203.0.113.6", host, "captcha")
	if got := h.MatchPassEntry(other+"~"+captcha, addr, host); got != captcha {
		t.Errorf("a two-network list: %q, want this address's entry", got)
	}
	for _, c := range []struct{ name, value, ip, host string }{
		{"another address", pow, "203.0.113.6", host},
		{"another host", pow, addr, "other.example"},
		{"no cookie", "", addr, host},
		{"junk", "not.a.cookie", addr, host},
	} {
		if got := h.MatchPassEntry(c.value, c.ip, c.host); got != "" {
			t.Errorf("%s: %q, want nothing", c.name, got)
		}
	}
	// Without a secret nothing can verify.
	h.SetSettings(settings.Settings{})
	if got := h.MatchPassEntry(pow, addr, host); got != "" {
		t.Errorf("no secret: %q, want nothing", got)
	}
}
