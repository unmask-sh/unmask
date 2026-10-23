package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The UA-TLS consistency tier (native): nginx names the contradiction on the
// internal rewrite, the serve records force_reason=ua_tls with it as the entry
// and shows the tier's screen (default CAPTCHA); a name nginx does not use is
// ignored, and the tier off or held by the upgrade review attributes nothing.
func TestUATLSServeAttributionAndScreen(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8"

	serve := func(mismatch string) (reason, chain string) {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", "t13d1517h2_8daaf6152771_dcad5a053991")
		if mismatch != "" {
			req.Header.Set("X-UA-TLS-Mismatch", mismatch)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		body := rr.Body.String()
		m := regexp.MustCompile(`/\*__CAPTCHA_FORCE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		c := regexp.MustCompile(`/\*__CHMODE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		if m == nil || c == nil {
			t.Fatalf("no force reason / chain in the served page (status %d)", rr.Code)
		}
		return m[1], c[1]
	}

	if reason, chain := serve("family"); reason != "ua_tls" || chain != settings.RateChallengeCaptchaOnly {
		t.Errorf("family: reason %q chain %q, want ua_tls captcha_only", reason, chain)
	}
	if reason, _ := serve("version"); reason != "ua_tls" {
		t.Errorf("version: reason %q, want ua_tls", reason)
	}
	if reason, _ := serve("bogus"); reason == "ua_tls" {
		t.Error("a name nginx does not use was attributed to the tier")
	}
	if reason, _ := serve(""); reason == "ua_tls" {
		t.Error("no header: attributed to the tier")
	}

	// The operator's screen.
	cur = h.snapshotSettings()
	cur.Global.UATLSConsistencyAction = settings.RateChallengePoWThenCaptcha
	h.SetSettings(cur)
	if _, chain := serve("family"); chain != settings.RateChallengePoWThenCaptcha {
		t.Errorf("chain %q, want the operator's pow_then_captcha", chain)
	}

	// Off: nothing.
	cur = h.snapshotSettings()
	cur.Global.UATLSConsistencyAction = ""
	cur.Global.UATLSConsistencyDisabled = true
	h.SetSettings(cur)
	if reason, _ := serve("family"); reason == "ua_tls" {
		t.Error("tier off: still attributed")
	}

	// Held by the upgrade review: nothing, until acknowledged.
	cur = h.snapshotSettings()
	cur.Global.UATLSConsistencyDisabled = false
	cur.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	cur.Nginx.EnforcementReviewedVersion = "v0.1.52"
	h.SetSettings(cur)
	if reason, _ := serve("family"); reason == "ua_tls" {
		t.Error("tier held: still attributed")
	}
	cur.Nginx.EnforcementReviewedVersion = settings.UATLSAddedIn
	h.SetSettings(cur)
	if reason, _ := serve("family"); reason != "ua_tls" {
		t.Errorf("acknowledged: reason %q, want ua_tls", reason)
	}

	// The entry behind the reason, for the serve and for a beacon echoing it.
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
	req.Header.Set("X-UA-TLS-Mismatch", "version")
	if e := h.forceEntry(req, "ua_tls", "", "", "", ""); e != "version" {
		t.Errorf("forceEntry = %q, want version", e)
	}
	if e := h.beaconForceEntry(req, map[string]any{"force_reason": "ua_tls", "force_rule": "family"}, "", ""); e != "family" {
		t.Errorf("beaconForceEntry = %q, want family", e)
	}
	if e := h.beaconForceEntry(req, map[string]any{"force_reason": "ua_tls", "force_rule": "made-up"}, "", ""); e != "" {
		t.Errorf("beaconForceEntry kept a name the tier does not use: %q", e)
	}
	if n := h.forceEntryName("ja", "ua_tls", "family"); n == "family" || n == "" {
		t.Errorf("forceEntryName = %q, want the localized label", n)
	}
}

// The resolver: blank and anything but a challenge chain is captcha_only.
func TestUATLSResolvedAction(t *testing.T) {
	var g settings.GlobalConfig
	if g.UATLSResolvedAction() != settings.RateChallengeCaptchaOnly || !g.UATLSEnabled() {
		t.Error("defaults: want captcha_only and enabled")
	}
	g.UATLSConsistencyAction = settings.RateChallengeDeny
	if g.UATLSResolvedAction() != settings.RateChallengeCaptchaOnly {
		t.Error("deny must not be honoured")
	}
	g.UATLSConsistencyAction = settings.RateChallengePoWOnly
	if g.UATLSResolvedAction() != settings.RateChallengePoWOnly {
		t.Error("pow_only not honoured")
	}
}
