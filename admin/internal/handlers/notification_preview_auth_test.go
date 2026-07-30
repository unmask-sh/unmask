package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Forward-auth wire of the guarded notification-preview rescue.  The UA alone
// must never pass -- these clients call from subscribers' own devices
// (residential IPs, no vendor ranges), so a UA-only rescue would be one
// copied header line -- and the Apple TLS fingerprint alone must not either.
// Mirrors the native "$unmask_notif_preview_ua$unmask_apple_tls" composite so
// both deploy modes answer the same visitor identically.
func TestNotificationPreviewGuardedRescue(t *testing.T) {
	const uaNotif = "NotificationExtension/3 CFNetwork/3826.600.41.2.1 Darwin/24.6.0"
	// Real Apple CFNetwork JA4 shape: the guard keys on the _b cipher hash.
	const ja4Apple = "t13d2014h2_a09f3c656075_14788d8d241b"
	// A different TLS stack carrying the copied UA (the cheap spoof).
	const ja4Other = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

	drive := func(s settings.Settings, ua, ja4 string) string {
		t.Helper()
		h := &Handler{RateLimiter: ratelimit.New()}
		if s.Secret.BVSecret == "" {
			s.Secret.BVSecret = "test-secret"
		}
		h.SetSettings(s)
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.RemoteAddr = "127.0.0.1:5555" // trusted peer, so X-Client-JA4 is honoured
		r.Header.Set("X-Original-URI", "/article/detail/123/")
		r.Header.Set("X-Original-IP", "203.0.113.60")
		r.Header.Set("X-Original-Host", "news.example.jp")
		r.Header.Set("User-Agent", ua)
		if ja4 != "" {
			r.Header.Set("X-Client-JA4", ja4)
		}
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result().Header.Get("X-Unmask-Action")
	}

	if got := drive(settings.Settings{}, uaNotif, ja4Apple); got != "pass" {
		t.Errorf("notification-preview UA + Apple TLS must pass, got %q", got)
	}
	if got := drive(settings.Settings{}, uaNotif, ja4Other); got == "pass" {
		t.Error("the copied UA on a non-Apple TLS stack must NOT pass")
	}
	if got := drive(settings.Settings{}, uaNotif, ""); got == "pass" {
		t.Error("no JA4 (plain HTTP / hidden client hello) must NOT pass on the UA alone")
	}
	// The pattern is anchored on the CFNetwork stack: naming the extension is
	// not enough even with a matching fingerprint from elsewhere.
	if got := drive(settings.Settings{}, "NotificationExtension/3", ja4Apple); got == "pass" {
		t.Error("bare NotificationExtension UA without CFNetwork must NOT pass")
	}

	// Operator controls behave like every other upstream group.
	off := settings.Settings{}
	off.Nginx.SearchBots.UpstreamGroupMode = map[string]string{
		classify.NotificationPreviewTag: classify.GroupModeNone,
	}
	if got := drive(off, uaNotif, ja4Apple); got == "pass" {
		t.Error("group mode none must disable the guarded rescue")
	}
	dis := settings.Settings{}
	dis.Nginx.SearchBots.UpstreamDisabled = []string{"Notification(Service)?Extension/.*CFNetwork"}
	if got := drive(dis, uaNotif, ja4Apple); got == "pass" {
		t.Error("per-pattern disable must disable the guarded rescue")
	}
}
