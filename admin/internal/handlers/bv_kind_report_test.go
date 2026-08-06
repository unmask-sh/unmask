package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The forward-auth wire must name the _bv entry that actually let the request
// through, not guess from the shape of the whole cookie.
//
// A _bv carries one signed entry per address the client has been seen on,
// joined by "~".  The old code counted dots across the entire value, so a real
// production cookie -- "<3-seg>.rebind~<4-seg>.pow2", five dots, neither form
// -- was filed as a CAPTCHA pass regardless of which half matched.  That is
// the same blindness the native plugin had: a crawler passing purely by
// re-binding read as steady CAPTCHA traffic while the PoW counters it never
// touched sat at zero.
func TestPickValidBVNamesTheMatchingEntry(t *testing.T) {
	h := newTestHandler(t)
	cfg := *h.cfg()
	cfg.Secret.BVSecret = "test-secret-for-bv-kind"
	const host = "example.test"

	solveIP := "203.0.113.10"
	roamIP := "198.51.100.20"

	// Built the way production builds one: a solve on the first address, then
	// a silent re-bind onto the second, both entries carried together.
	powEntry := cookies.IssueValue(cfg.Secret.BVSecret, solveIP, host, "pow")
	rebindEntry := cookies.IssueValue(cfg.Secret.BVSecret, roamIP, host, "rebind")
	captchaEntry := cookies.IssueValue(cfg.Secret.BVSecret, solveIP, host, "captcha")

	ask := func(value, ip string) (string, string) {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.Host = host
		r.AddCookie(&http.Cookie{Name: "_bv", Value: value})
		return pickValidBV(r, cfg, ip, "")
	}

	t.Run("multi-entry cookie reports the entry that matched this IP", func(t *testing.T) {
		got, kind := ask(rebindEntry+"~"+powEntry, roamIP)
		if got == "" {
			t.Fatal("the re-bound entry should verify from the roamed address")
		}
		if kind != "rebind" {
			t.Fatalf("kind = %q, want \"rebind\" (the entry that matched), not the shape of the pair", kind)
		}
	})

	t.Run("same cookie from the solving address reports the solve", func(t *testing.T) {
		// Nothing about the cookie changed -- only where the request came
		// from -- so a shape-based reading cannot tell these two apart.
		if _, kind := ask(rebindEntry+"~"+powEntry, solveIP); kind != "pow" {
			t.Fatalf("kind = %q, want \"pow\"", kind)
		}
	})

	t.Run("a genuine CAPTCHA solve is still captcha", func(t *testing.T) {
		if _, kind := ask(captchaEntry, solveIP); kind != "captcha" {
			t.Fatalf("kind = %q, want \"captcha\"", kind)
		}
	})

	t.Run("no matching entry yields nothing", func(t *testing.T) {
		if v, kind := ask(rebindEntry, "192.0.2.99"); v != "" || kind != "" {
			t.Fatalf("unrelated address must not verify, got value=%q kind=%q", v, kind)
		}
	})
}

// normalizeBVKind exists so the counters keep one name per concept: the
// 4-segment form signs itself "pow2" but has always been aggregated as "pow".
func TestNormalizeBVKind(t *testing.T) {
	for in, want := range map[string]string{
		"pow2":    "pow",
		"captcha": "captcha",
		"rebind":  "rebind",
		// An admin newer than this build minting a kind it has not heard of
		// must show up as itself rather than be flattened into a wrong one.
		"passkey": "passkey",
		"":        "",
	} {
		if got := normalizeBVKind(in); got != want {
			t.Errorf("normalizeBVKind(%q) = %q, want %q", in, got, want)
		}
	}
}

var _ = settings.Settings{}
