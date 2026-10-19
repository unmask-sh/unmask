package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A custom rule's challenge names the rule: the page carries the id for its
// beacons, the serve row records it, and a beacon's force_rule is kept only
// when it names one of this install's rules.
func TestCustomRuleChallengeNamesWhichRule(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1a2b", Label: "the scraper", Enabled: true}}
	h.SetSettings(cur)

	const plainUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	serve := func(hdr map[string]string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", plainUA)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		m := regexp.MustCompile(`/\*__FORCE_RULE__\*/"([^"]*)"`).FindStringSubmatch(rr.Body.String())
		if m == nil {
			t.Fatalf("no force_rule in the served page (status %d)", rr.Code)
		}
		return m[1]
	}
	latest := func(phase, marker string) string {
		t.Helper()
		var payload string
		for i := 0; i < 150 && !strings.Contains(payload, marker); i++ {
			time.Sleep(20 * time.Millisecond)
			_ = h.DB.QueryRow(`SELECT COALESCE(payload_json, '') FROM unmask_event WHERE phase = ? ORDER BY id DESC LIMIT 1`, phase).Scan(&payload)
		}
		return payload
	}

	if got := serve(map[string]string{"X-Unmask-Rule": "cr1a2b", "X-Unmask-Rule-Action": "captcha_only"}); got != "cr1a2b" {
		t.Errorf("the page names rule %q, want cr1a2b", got)
	}
	if p := latest("serve", `"force_rule"`); !strings.Contains(p, `"force_rule":"cr1a2b"`) || !strings.Contains(p, `"force_reason":"custom_rule"`) {
		t.Errorf("the serve row does not name the rule: %s", p)
	}
	// No rule, a rule that only watches, and an id that is not one: none named.
	for _, hdr := range []map[string]string{
		nil,
		{"X-Unmask-Rule": "cr1a2b", "X-Unmask-Rule-Action": "monitor"},
		{"X-Unmask-Rule": "../x", "X-Unmask-Rule-Action": "captcha_only"},
	} {
		if got := serve(hdr); got != "" {
			t.Errorf("%v: the page names rule %q, want none", hdr, got)
		}
	}

	// The beacon keeps a rule of ours and drops anything else.
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	beacon := func(rule, marker string) string {
		t.Helper()
		body := `{"phase":"load","flags":0,"reload_count":0,"ua":"` + marker + `","force_reason":"custom_rule","force_rule":"` + rule + `","bt":"` + bt + `"}`
		req := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "1.2.3.4")
		rr := httptest.NewRecorder()
		h.DebugBeacon(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("beacon %s: %d %s", marker, rr.Code, rr.Body.String())
		}
		return latest("load", `"ua":"`+marker+`"`)
	}
	if p := beacon("cr1a2b", "m1"); !strings.Contains(p, `"force_rule":"cr1a2b"`) {
		t.Errorf("a beacon naming our rule lost it: %s", p)
	}
	if p := beacon("crzzzz", "m2"); strings.Contains(p, "force_rule") {
		t.Errorf("a beacon naming a rule we do not have kept it: %s", p)
	}
	if p := beacon("", "m3"); strings.Contains(p, "force_rule") {
		t.Errorf("a beacon naming no rule kept the key: %s", p)
	}
}
