package handlers

import (
	"crypto/sha256"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// bvjTestDifficulty: the proof-of-work difficulty the /bvj tests solve at.
const bvjTestDifficulty = 8

// powPass solves the proof-of-work the challenge page hands a client bound to
// key on host and returns the _bv entry challenge.js writes for it.  The
// nonce must clear none of the foreign keys' seeds: at this difficulty one in
// 256 would, and the test asserting the entry is refused for them would then
// fail at random.
func powPass(t *testing.T, secret, key, host string, foreign ...string) string {
	t.Helper()
	return powPassAvoiding(t, secret, key, host, foreign, nil)
}

// powPassAvoiding is powPass with the seeds the nonce must NOT clear spelt
// out: those of the foreign keys on host, and those of key on the foreign
// hosts -- under every SigHash, since the verifier derives the seed with each
// (cookies.SigHashes) and would accept the entry for a foreign key or host
// whose seed the nonce happens to answer.
func powPassAvoiding(t *testing.T, secret, key, host string, foreignKeys, foreignHosts []string) string {
	t.Helper()
	issued := time.Now().Unix()
	clears := func(seed string, nonce int64) bool {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		n := 0
		for _, b := range sum {
			if b != 0 {
				n += bits.LeadingZeros8(b)
				break
			}
			n += 8
		}
		return n >= bvjTestDifficulty
	}
	own := cookies.PowSeed(secret, key, host, issued)
	var avoid []string
	for _, h := range cookies.SigHashes {
		for _, f := range foreignKeys {
			avoid = append(avoid, cookies.PowSeedH(h, secret, f, host, issued))
		}
		for _, fh := range foreignHosts {
			avoid = append(avoid, cookies.PowSeedH(h, secret, key, fh, issued))
		}
	}
next:
	for nonce := int64(0); nonce < 1<<24; nonce++ {
		if !clears(own, nonce) {
			continue
		}
		for _, seed := range avoid {
			if clears(seed, nonce) {
				continue next
			}
		}
		return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
	}
	t.Fatal("no nonce clears the difficulty")
	return ""
}

// A pass issued inside a relay is bound to the relay's key (X-Unmask-Bind-Key),
// and the plugin verifies it with that key.  /bvj must check it the same way,
// or a visitor behind the relay never gets the credential that rebinds them
// once the relay moves them elsewhere or they leave it.
func TestIssueBVJ_BindKey(t *testing.T) {
	const secret, host, addr = "test-secret", "example.com", "203.0.113.5"
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	h := newRebindTestHandler(t)
	h.SetSettings(settings.Settings{
		Secret:    settings.Secret{BVSecret: secret},
		Challenge: settings.ChallengeConfig{Default: settings.ChallengeValues{PowDifficulty: bvjTestDifficulty}},
	})
	post := func(bv, key string) (*httptest.ResponseRecorder, string) {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/bvj", nil)
		req.Host = host
		req.Header.Set("X-Real-IP", addr)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		if key != "" {
			req.Header.Set("X-Unmask-Bind-Key", key)
		}
		req.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		rr := httptest.NewRecorder()
		h.IssueBVJ(rr, req)
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_bvj" {
				return rr, c.Value
			}
		}
		return rr, ""
	}

	for _, key := range []string{"zscaler", "192.0.2.192/26"} {
		bv := powPass(t, secret, key, host, addr)
		if rr, bvj := post(bv, key); rr.Code != http.StatusOK || bvj == "" {
			t.Errorf("key %q: status %d body %s, want a _bvj for the pass bound to the key", key, rr.Code, rr.Body.String())
		}
		// Without the key the request is the address's, and the pass is not:
		// refused, as the plugin refuses it.
		if rr, bvj := post(bv, ""); rr.Code != http.StatusForbidden || bvj != "" {
			t.Errorf("key %q, none on the request: status %d, want 403 and no _bvj", key, rr.Code)
		}
	}
	// Outside a relay the address is the key, as before.
	if rr, bvj := post(powPass(t, secret, addr, host, "zscaler"), ""); rr.Code != http.StatusOK || bvj == "" {
		t.Errorf("address-bound pass: status %d body %s, want a _bvj", rr.Code, rr.Body.String())
	}
	// Inside one, a pass bound to the address does not pass the plugin, so it
	// earns no _bvj either.
	if rr, _ := post(powPass(t, secret, addr, host, "zscaler"), "zscaler"); rr.Code != http.StatusForbidden {
		t.Errorf("address-bound pass inside a relay: status %d, want 403", rr.Code)
	}

	// What the _bvj is for: the visitor leaves the relay, and the challenge
	// route rebinds their pass to the new address without a challenge.
	bv := powPass(t, secret, "zscaler", host, addr)
	_, bvj := post(bv, "zscaler")
	if bvj == "" {
		t.Fatal("no _bvj to rebind with")
	}
	const home = "198.51.100.7"
	req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/?_orig=%2Forder%2Fform", nil)
	req.Host = host
	req.Header.Set("X-Real-IP", home)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Client-JA4", ja4)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
	rr := httptest.NewRecorder()
	h.ServeChallengeOrJSON(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Unmask-Mode") != "rebind" {
		t.Fatalf("left the relay: status %d mode %q, want the rebind bounce", rr.Code, rr.Header().Get("X-Unmask-Mode"))
	}
	var rebound string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			rebound = strings.SplitN(c.Value, "~", 2)[0]
		}
	}
	if !cookies.Verify(rebound, secret, home, host, 7*86400, 14*86400, bvjTestDifficulty) {
		t.Errorf("the rebound entry %q must verify for the new address %s", rebound, home)
	}
}
