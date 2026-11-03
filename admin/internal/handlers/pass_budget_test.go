package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func passBeaconJA4(h *Handler, ip, host, ja4, phase, bv string) *httptest.ResponseRecorder {
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/unmask/api/debug",
		strings.NewReader(`{"phase":"`+phase+`","flags":0,"reload_count":0,"ua":"x","bt":"`+bt+`"}`))
	r.Host = host
	r.Header.Set("X-Real-IP", ip)
	r.Header.Set("X-Client-JA4", ja4)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	rr := httptest.NewRecorder()
	h.DebugBeacon(rr, r)
	return rr
}

// TestPassBudgetBansAPageByPageSolver: a client whose recorded proof-of-work
// passes run past the day's budget is banned, address and fingerprint
// together, under the budget's action and source; a CAPTCHA pass, a bypass
// address, the day after a settings change every client re-solves for, a
// budget held by the upgrade review and a budget switched off ban nobody.
func TestPassBudgetBansAPageByPageSolver(t *testing.T) {
	h := passTraceHandler(t)
	h.BanMgr = ban.New(h.DB, filepath.Join(t.TempDir(), "ban.list"), time.Hour)
	s := *h.cfg()
	s.RateLimit.PassBudget.PerDay = 3
	s.Nginx.BypassIPs = []string{"198.51.100.99"}
	h.SetSettings(s)
	const host, ja4 = "example.com", "t13d1517h2_8daaf6152771_dcad5a053991"
	ctx := context.Background()
	solve := func(ip string, i int) {
		t.Helper()
		bv := powPassAt(t, h.cfg().Secret.BVSecret, ip, host, time.Now().Unix()-int64(i))
		if rr := passBeaconJA4(h, ip, host, ja4, "bv_pow_only", bv); rr.Code != http.StatusOK {
			t.Fatalf("pass beacon %d answered %d %s", i, rr.Code, rr.Body.String())
		}
	}
	banned := func(ip string) (action, source string, ok bool) {
		return h.BanMgr.IsBannedActionSource(ctx, ip, ja4)
	}

	const bot = "198.51.100.51"
	for i := 1; i <= 3; i++ {
		solve(bot, i)
	}
	if _, _, b := banned(bot); b {
		t.Fatal("banned within the budget")
	}
	solve(bot, 4)
	act, src, b := banned(bot)
	if !b || src != ban.SourceRateLimitAbuse || act != settings.RateChallengeCaptchaOnly {
		t.Fatalf("over the budget: banned=%v source=%q action=%q, want rate_limit_abuse captcha_only", b, src, act)
	}
	if _, _, b := h.BanMgr.IsBannedActionSource(ctx, bot, "t13d1516h2_other_ja4"); b {
		t.Error("the ban reached another fingerprint of the address")
	}
	solve(bot, 5) // still banned, no second ban, no error

	// A CAPTCHA pass counts like a proof-of-work pass (the built-in CAPTCHA
	// is answered by a script in two requests, so a run of them is the same
	// client this budget exists for).
	for i := 0; i < 4; i++ {
		h.countPass("198.51.100.52", ja4, "", "captcha", "")
	}
	if _, _, b := banned("198.51.100.52"); !b {
		t.Error("CAPTCHA passes were not counted")
	}
	// A re-bound pass is not a solve.
	for i := 0; i < 10; i++ {
		h.countPass("198.51.100.54", ja4, "", "rebind", "")
	}
	if _, _, b := banned("198.51.100.54"); b {
		t.Error("re-bound passes were counted")
	}

	// A bypass address is not counted.
	for i := 1; i <= 6; i++ {
		solve("198.51.100.99", i)
	}
	if _, _, b := banned("198.51.100.99"); b {
		t.Error("a bypass address was banned")
	}

	// The cookie secret changes: everyone re-solves, nobody is banned for a day.
	s = *h.cfg()
	s.Secret.BVSecret = "rotated-secret"
	h.SetSettings(s)
	for i := 1; i <= 6; i++ {
		solve("198.51.100.53", i)
	}
	if _, _, b := banned("198.51.100.53"); b {
		t.Error("banned while the budget settles after a secret change")
	}

	// Held by the upgrade review, and switched off: nothing.
	for _, mutate := range []func(*settings.Settings){
		func(s *settings.Settings) {
			s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
			s.Nginx.EnforcementReviewedVersion = "v0.1.52"
		},
		func(s *settings.Settings) { s.RateLimit.PassBudget.Disabled = true },
	} {
		h := passTraceHandler(t)
		h.BanMgr = ban.New(h.DB, filepath.Join(t.TempDir(), "ban.list"), time.Hour)
		s := *h.cfg()
		s.RateLimit.PassBudget.PerDay = 3
		mutate(&s)
		h.SetSettings(s)
		if nginxconf.PassBudgetActive(s) {
			t.Fatal("the budget reads as active")
		}
		for i := 1; i <= 6; i++ {
			bv := powPassAt(t, s.Secret.BVSecret, "198.51.100.54", host, time.Now().Unix()-int64(i))
			passBeaconJA4(h, "198.51.100.54", host, ja4, "bv_pow_only", bv)
		}
		if _, _, b := h.BanMgr.IsBannedActionSource(ctx, "198.51.100.54", ja4); b {
			t.Error("banned while the budget is held or off")
		}
	}
	var held bool
	for _, p := range nginxconf.HeldEnforcementPresets(func() settings.Settings {
		var s settings.Settings
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = "v0.1.52"
		return s
	}()) {
		held = held || p.ID == "pass_budget"
	}
	if !held {
		t.Error("the held list does not name the budget")
	}
}

// TestPassBudgetResolvers: the seeds and the clamp.
func TestPassBudgetResolvers(t *testing.T) {
	var c settings.PassBudgetConfig
	if c.ResolvedPerDay() != settings.PassBudgetSeedPerDay || c.ResolvedBanHours() != settings.PassBudgetSeedBanHours || c.ResolvedAction() != settings.RateChallengeCaptchaOnly || !c.IsZero() {
		t.Error("defaults")
	}
	c = settings.PassBudgetConfig{PerDay: 40, BanHours: 2, Action: settings.RateChallengeDeny}
	if c.ResolvedPerDay() != 40 || c.ResolvedBanHours() != 2 || c.ResolvedAction() != settings.RateChallengeDeny || c.IsZero() {
		t.Error("stored values")
	}
	c.Action = settings.RateChallengePoWOnly
	if c.ResolvedAction() != settings.RateChallengeCaptchaOnly {
		t.Error("an action other than deny resolves to captcha_only")
	}
}

// TestPassBudgetCountsDistinctPasses: a pass is one however many traces
// report it -- the page's beacon and the access log naming the same pass
// count once -- and the log alone, with no beacon ever sent, carries a
// client to the ban: the passes an address presents are what the daemon
// sees of a client that mints its cookies itself.  The log names the
// proof-of-work kind the plugin's way ("pow").
func TestPassBudgetCountsDistinctPasses(t *testing.T) {
	h := passTraceHandler(t)
	h.BanMgr = ban.New(h.DB, filepath.Join(t.TempDir(), "ban.list"), time.Hour)
	s := *h.cfg()
	s.RateLimit.PassBudget.PerDay = 3
	h.SetSettings(s)
	const host, ja4 = "example.com", "t13d1517h2_8daaf6152771_dcad5a053991"
	ctx := context.Background()
	banned := func(ip string) bool {
		_, _, b := h.BanMgr.IsBannedActionSource(ctx, ip, ja4)
		return b
	}

	// One pass, reported by the beacon and seen in the log many times.
	const quiet = "198.51.100.61"
	bv := powPassAt(t, h.cfg().Secret.BVSecret, quiet, host, time.Now().Unix()-2)
	if rr := passBeaconJA4(h, quiet, host, ja4, "bv_pow_only", bv); rr.Code != http.StatusOK {
		t.Fatalf("pass beacon answered %d %s", rr.Code, rr.Body.String())
	}
	id := h.PassIdentity(bv, quiet, host)
	if id == "" {
		t.Fatal("the pass has no identity")
	}
	for i := 0; i < 10; i++ {
		h.ObservePass(quiet, ja4, "", "pow", id)
	}
	if banned(quiet) {
		t.Error("one pass, reported through two traces, was counted past the budget")
	}

	// A client that never reports: the log alone.
	const silent = "198.51.100.62"
	for i := 1; i <= 3; i++ {
		h.ObservePass(silent, ja4, "", "pow", fmt.Sprintf("pass-%d", i))
		h.ObservePass(silent, ja4, "", "pow", fmt.Sprintf("pass-%d", i)) // the same pass again
	}
	if banned(silent) {
		t.Fatal("banned within the budget")
	}
	h.ObservePass(silent, ja4, "", "captcha", "pass-4")
	if !banned(silent) {
		t.Error("a client whose passes the log shows past the budget was not banned")
	}
	// A kind the budget does not count.
	const roaming = "198.51.100.63"
	for i := 1; i <= 6; i++ {
		h.ObservePass(roaming, ja4, "", "rebind", fmt.Sprintf("pass-%d", i))
	}
	if banned(roaming) {
		t.Error("re-bound passes from the log were counted")
	}
}
