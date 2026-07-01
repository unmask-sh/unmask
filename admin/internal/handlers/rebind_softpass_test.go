package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// newRebindTestHandler builds a Handler on a fully-migrated sqlite DB (so the
// rebind lineage table exists) with rebind enabled by default and no ASN db
// (the ASN veto degrades to skipped).
func newRebindTestHandler(t *testing.T) *Handler {
	t.Helper()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "rb.sqlite")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := &Handler{DB: conn}
	h.SetSettings(settings.Settings{Secret: settings.Secret{BVSecret: "test-secret"}})
	return h
}

// TestVerdictIsBot locks the verdict gate A uses: preset bot signatures count as
// bot-like; ok / empty / unknown do not (fail open).
func TestVerdictIsBot(t *testing.T) {
	h := newRebindTestHandler(t)
	cases := []struct {
		v    string
		want bool
	}{
		{"chrome_fake_h1", true}, // preset bot verdict
		{"noalpn_311", true},     // preset bot verdict
		{"ok", false},
		{"", false},                    // unset header -> not bot
		{"nonexistent_verdict", false}, // unknown name -> not bot
	}
	for _, c := range cases {
		if got := h.verdictIsBot(c.v); got != c.want {
			t.Errorf("verdictIsBot(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

// TestTryRebindJA4Drift exercises A+B end-to-end on the rebind gate:
//   - a JA4 already in the _bvj set rebinds silently (B, baseline)
//   - a drifted JA4 (the h2<->h3 transport the device hasn't re-solved under)
//     with a clean verdict is let through and flagged (A: soft-pass)
//   - a drifted JA4 that looks bot-like is still vetoed
func TestTryRebindJA4Drift(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4H2 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"  // solve transport (in the set)
	const ja4H3 = "q13d0311h3_55b375c5d22e_653d80c3fe9d"  // QUIC drift (not in the set)
	const ja4Bot = "t13d1812h1_85036bcba153_deadbeef0001" // matches preset verdict h1_18_12 (bot)

	uah := cookies.FingerprintHash(ua)
	bvjFor := func() string {
		// _bvj minted under the h2 transport only (single-hash set).
		return cookies.IssueJValue("test-secret", cookies.FingerprintHash(ja4H2), uah,
			"linrebind0000000000000000", 0, "example.com", "captcha")
	}
	mk := func(curJA4, verdict string) (*Handler, *httptest.ResponseRecorder, *http.Request) {
		h := newRebindTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", curJA4)
		if verdict != "" {
			req.Header.Set("X-JA4-Verdict", verdict)
		}
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvjFor()})
		return h, httptest.NewRecorder(), req
	}
	bvIssued := func(rr *httptest.ResponseRecorder) bool {
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_bv" {
				return true
			}
		}
		return false
	}

	t.Run("JA4 in set -> silent rebind", func(t *testing.T) {
		h, rr, req := mk(ja4H2, "ok")
		if !h.tryRebind(rr, req, "default") {
			t.Fatal("a JA4 in the _bvj set should rebind")
		}
		if !bvIssued(rr) {
			t.Error("rebind should issue a fresh _bv")
		}
	})

	t.Run("h3 drift + clean verdict -> soft-pass", func(t *testing.T) {
		h, rr, req := mk(ja4H3, "ok")
		if !h.tryRebind(rr, req, "default") {
			t.Fatal("a clean (non-bot) JA4 drift should soft-pass the rebind")
		}
		if !bvIssued(rr) {
			t.Error("soft-pass should issue a fresh _bv")
		}
	})

	t.Run("drift + bot verdict -> vetoed", func(t *testing.T) {
		h, rr, req := mk(ja4Bot, "h1_18_12")
		if h.tryRebind(rr, req, "default") {
			t.Fatal("a bot-like JA4 drift must be refused, not soft-passed")
		}
		if bvIssued(rr) {
			t.Error("a refused rebind must not issue a _bv")
		}
	})
}
