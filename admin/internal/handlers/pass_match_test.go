package handlers

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
	"strings"
	"testing"
	"time"

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

// PassIdentity names the pass the way the plugin's $unmask_bv_id does, for the
// per-address count of distinct passes: two nonces that answer one
// proof-of-work seed are one pass (one budget under the per-pass reuse cap),
// a seed of another second is another, a CAPTCHA entry is named by its
// signature, and nothing that does not verify is named at all.
func TestPassIdentityNamesTheBudget(t *testing.T) {
	const secret, host, addr = "test-secret", "example.com", "203.0.113.5"
	h := newRebindTestHandler(t)
	h.SetSettings(settings.Settings{
		Secret:    settings.Secret{BVSecret: secret},
		Challenge: settings.ChallengeConfig{Default: settings.ChallengeValues{PowDifficulty: bvjTestDifficulty}},
	})
	now := time.Now().Unix()
	a := powPassAt(t, secret, addr, host, now)
	// A second nonce for the same seed: the search goes on past the first.
	seed := cookies.PowSeed(secret, addr, host, now)
	first, _ := strconv.ParseInt(strings.Split(a, ".")[2], 36, 64)
	b := ""
	for nonce := first + 1; nonce < first+1<<24 && b == ""; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		n := 0
		for _, x := range sum {
			if x != 0 {
				n += bits.LeadingZeros8(x)
				break
			}
			n += 8
		}
		if n >= bvjTestDifficulty {
			b = strconv.FormatInt(now, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	if b == "" || b == a {
		t.Fatal("no second nonce for the seed")
	}
	ida, idb := h.PassIdentity(a, addr, host), h.PassIdentity(b, addr, host)
	if ida == "" || ida != seed[:cookies.PassIDLen] {
		t.Errorf("a PoW pass: %q, want the seed's first digits %q", ida, seed[:cookies.PassIDLen])
	}
	if idb != ida {
		t.Errorf("another nonce of the seed: %q, want the same pass %q", idb, ida)
	}
	if other := h.PassIdentity(powPassAt(t, secret, addr, host, now-1), addr, host); other == ida || other == "" {
		t.Errorf("a pass of the second before: %q, want a pass of its own", other)
	}
	// The identity follows the entry that verifies, wherever it sits.
	if got := h.PassIdentity("1785943030.pow2.zzzz.0~"+a+"~garbage", addr, host); got != ida {
		t.Errorf("a padded value: %q, want %q", got, ida)
	}
	captcha := cookies.IssueValue(secret, addr, host, "captcha")
	if got := h.PassIdentity(captcha, addr, host); got != strings.Split(captcha, ".")[1] {
		t.Errorf("a CAPTCHA entry: %q, want its signature", got)
	}
	for _, c := range []struct{ name, value, ip string }{
		{"another address", a, "203.0.113.6"},
		{"no cookie", "", addr},
		{"junk", "not.a.cookie", addr},
	} {
		if got := h.PassIdentity(c.value, c.ip, host); got != "" {
			t.Errorf("%s: %q, want nothing", c.name, got)
		}
	}
}
