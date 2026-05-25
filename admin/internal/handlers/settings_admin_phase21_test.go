// Phase 2.1 unit tests for the per-site editor on the challenge /
// rate_limit / honeypot tabs.  Default-scope behaviour must stay identical
// to the pre-scope helpers; site-scope writes must land in Overrides[scope]
// as sparse entries; empty overrides must be cleaned up; the reset flag
// must drop the whole entry.
package handlers

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// --- Challenge ---

func TestApplyChallengeFormScopedDefault(t *testing.T) {
	c := &settings.Challenge{
		Theme:         "default",
		PowDifficulty: 18,
		ShowCredit:    false,
		Overrides: map[string]settings.ChallengeOverride{
			"shop.example.com": {Theme: "cat"},
		},
	}
	body := url.Values{
		"pow_difficulty":         []string{"20"},
		"public_test_pages_present": []string{"1"},
		"public_test_pages":      []string{"1"},
		"show_credit":            []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyChallengeFormScoped(c, r, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.PowDifficulty != 20 {
		t.Errorf("PowDifficulty default-scope write = %d, want 20", c.PowDifficulty)
	}
	if !c.ShowCredit {
		t.Errorf("ShowCredit default-scope write = false, want true")
	}
	if !c.PublicTestPages {
		t.Errorf("PublicTestPages default-scope write = false, want true")
	}
	if _, ok := c.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch sibling Overrides")
	}
}

func TestApplyChallengeFormScopedSiteCreate(t *testing.T) {
	c := &settings.Challenge{
		Theme:         "default",
		PowDifficulty: 18,
		ShowCredit:    false,
	}
	body := url.Values{
		"theme":                []string{"cat"},
		"pow_difficulty":       []string{"20"},
		"show_credit_override": []string{"on"},
	}
	r := formReq(t, body.Encode())
	if err := applyChallengeFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.PowDifficulty != 18 {
		t.Errorf("site scope must not touch baseline PowDifficulty; got %d", c.PowDifficulty)
	}
	ov, ok := c.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("Overrides[shop.example.com] missing")
	}
	if ov.Theme != "cat" || ov.PowDifficulty != 20 || ov.ShowCredit != true || !ov.ShowCreditSet {
		t.Errorf("override = %+v, want {Theme:cat PowDifficulty:20 ShowCredit:true ShowCreditSet:true}", ov)
	}
}

func TestApplyChallengeFormScopedSiteAllBlankDrops(t *testing.T) {
	c := &settings.Challenge{
		Overrides: map[string]settings.ChallengeOverride{
			"shop.example.com": {Theme: "cat", PowDifficulty: 20},
			"blog.example.com": {ShowCredit: true, ShowCreditSet: true},
		},
	}
	body := url.Values{
		"theme":                []string{"inherit"},
		"pow_difficulty":       []string{""},
		"show_credit_override": []string{"inherit"},
	}
	r := formReq(t, body.Encode())
	if err := applyChallengeFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := c.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank site scope must delete the override; map=%+v", c.Overrides)
	}
	if _, ok := c.Overrides["blog.example.com"]; !ok {
		t.Errorf("sibling override must survive; map=%+v", c.Overrides)
	}
}

func TestApplyChallengeFormScopedReset(t *testing.T) {
	c := &settings.Challenge{
		Overrides: map[string]settings.ChallengeOverride{
			"shop.example.com": {Theme: "cat"},
			"blog.example.com": {PowDifficulty: 22},
		},
	}
	body := url.Values{
		"theme":            []string{"cat"},
		"reset_challenge":  []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyChallengeFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := c.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", c.Overrides)
	}
	if _, ok := c.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides; map=%+v", c.Overrides)
	}
}

func TestApplyChallengeFormScopedSiteShowCreditOff(t *testing.T) {
	// Explicit "off" must set ShowCredit=false + ShowCreditSet=true so the
	// site overrides a default of true.
	c := &settings.Challenge{ShowCredit: true}
	body := url.Values{"show_credit_override": []string{"off"}}
	r := formReq(t, body.Encode())
	if err := applyChallengeFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	ov := c.Overrides["shop.example.com"]
	if ov.ShowCredit != false || !ov.ShowCreditSet {
		t.Errorf("override = %+v, want {ShowCredit:false ShowCreditSet:true}", ov)
	}
}

// --- RateLimit ---

func TestApplyRateLimitFormScopedDefault(t *testing.T) {
	c := &settings.RateLimitConfig{
		Default: settings.RateZone{Name: "unmask_rate", RequestsPerMin: 100, Burst: 50, WindowSec: 60, ChallengeMode: "pow_then_captcha"},
		Overrides: map[string]settings.RateLimitOverride{
			"shop.example.com": {RequestsPerMin: 200},
		},
	}
	body := url.Values{
		"default_requests_per_min": []string{"150"},
		"default_burst":            []string{"30"},
		"default_window_sec":       []string{"45"},
		"default_challenge_mode":   []string{"captcha_only"},
	}
	r := formReq(t, body.Encode())
	if err := applyRateLimitFormScoped(c, r, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.Default.RequestsPerMin != 150 || c.Default.Burst != 30 || c.Default.WindowSec != 45 {
		t.Errorf("default zone after default-scope write = %+v", c.Default)
	}
	if c.Default.ChallengeMode != "captcha_only" {
		t.Errorf("default ChallengeMode = %q, want captcha_only", c.Default.ChallengeMode)
	}
	if _, ok := c.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch sibling Overrides")
	}
}

func TestApplyRateLimitFormScopedSiteCreate(t *testing.T) {
	c := &settings.RateLimitConfig{
		Default: settings.RateZone{Name: "unmask_rate", RequestsPerMin: 100, Burst: 50, WindowSec: 60, ChallengeMode: "pow_then_captcha"},
	}
	body := url.Values{
		"default_requests_per_min": []string{"200"},
		"default_burst":            []string{"0"},
		"burst_override_set":       []string{"1"},
		"default_window_sec":       []string{"30"},
		"default_challenge_mode":   []string{"captcha_only"},
	}
	r := formReq(t, body.Encode())
	if err := applyRateLimitFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.Default.RequestsPerMin != 100 {
		t.Errorf("site scope must not touch baseline; got %d", c.Default.RequestsPerMin)
	}
	ov, ok := c.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("Overrides[shop.example.com] missing")
	}
	if ov.RequestsPerMin != 200 || ov.Burst != 0 || !ov.BurstSet || ov.WindowSec != 30 || ov.ChallengeMode != "captcha_only" {
		t.Errorf("override = %+v", ov)
	}
}

func TestApplyRateLimitFormScopedBurstInheritWithoutSet(t *testing.T) {
	c := &settings.RateLimitConfig{
		Default: settings.RateZone{Name: "unmask_rate", RequestsPerMin: 100, Burst: 50},
	}
	body := url.Values{
		"default_burst": []string{"999"}, // ignored without burst_override_set=1
	}
	r := formReq(t, body.Encode())
	if err := applyRateLimitFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := c.Overrides["shop.example.com"]; ok {
		t.Errorf("burst without override_set must not create an entry; map=%+v", c.Overrides)
	}
}

func TestApplyRateLimitFormScopedSiteAllBlankDrops(t *testing.T) {
	c := &settings.RateLimitConfig{
		Overrides: map[string]settings.RateLimitOverride{
			"shop.example.com": {RequestsPerMin: 200},
			"blog.example.com": {ChallengeMode: "deny"},
		},
	}
	body := url.Values{
		"default_requests_per_min": []string{""},
		"default_window_sec":       []string{""},
		"default_challenge_mode":   []string{"inherit"},
	}
	r := formReq(t, body.Encode())
	if err := applyRateLimitFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := c.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank site scope must delete the override; map=%+v", c.Overrides)
	}
	if _, ok := c.Overrides["blog.example.com"]; !ok {
		t.Errorf("sibling override must survive")
	}
}

func TestApplyRateLimitFormScopedReset(t *testing.T) {
	c := &settings.RateLimitConfig{
		Overrides: map[string]settings.RateLimitOverride{
			"shop.example.com": {RequestsPerMin: 200},
			"blog.example.com": {ChallengeMode: "deny"},
		},
	}
	body := url.Values{
		"default_requests_per_min": []string{"200"},
		"reset_rate_limit":         []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyRateLimitFormScoped(c, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := c.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", c.Overrides)
	}
	if _, ok := c.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides")
	}
}

// --- Honeypot ---

func TestApplyHoneypotFormScopedDefault(t *testing.T) {
	n := &settings.Nginx{
		Honeypot: settings.HoneypotConfig{
			Extra:         []string{"/old"},
			ExtraTitle:    []string{"old"},
			ExtraDisabled: []bool{false},
			ExtraUpdatedAt: []int64{1},
			DefaultAction: "pow_then_captcha",
			BanDuration:   86400,
			Overrides: map[string]settings.HoneypotOverride{
				"shop.example.com": {AppendExtra: []string{"/shop-trap"}},
			},
		},
	}
	body := url.Values{
		"ban_duration":            []string{"3600"},
		"honeypot_pat":            []string{"/wp-login.php"},
		"honeypot_title":          []string{"wp"},
		"honeypot_enabled":        []string{"1"},
		"honeypot_updated_at":     []string{"0"},
		"honeypot_default_action": []string{"deny"},
	}
	r := formReq(t, body.Encode())
	if err := applyHoneypotFormScoped(n, r, i18n.LangEN, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if n.Honeypot.BanDuration != 3600 {
		t.Errorf("default-scope BanDuration = %d, want 3600", n.Honeypot.BanDuration)
	}
	if len(n.Honeypot.Extra) != 1 || n.Honeypot.Extra[0] != "/wp-login.php" {
		t.Errorf("default-scope Extra not rewritten verbatim: %+v", n.Honeypot.Extra)
	}
	if n.Honeypot.DefaultAction != "deny" {
		t.Errorf("default-scope DefaultAction = %q, want deny", n.Honeypot.DefaultAction)
	}
	if _, ok := n.Honeypot.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch sibling Overrides")
	}
}

func TestApplyHoneypotFormScopedSiteCreate(t *testing.T) {
	n := &settings.Nginx{
		Honeypot: settings.HoneypotConfig{
			Extra:         []string{"/wp-login.php", "/xmlrpc.php"},
			ExtraTitle:    []string{"wp", "xmlrpc"},
			ExtraDisabled: []bool{false, false},
			ExtraUpdatedAt: []int64{1, 2},
			DefaultAction: "pow_then_captcha",
		},
	}
	body := url.Values{
		"honeypot_pat":              []string{"^/shop-trap"},
		"honeypot_title":            []string{"shop honeypot"},
		"honeypot_enabled":          []string{"1"},
		"honeypot_updated_at":       []string{"0"},
		"honeypot_extra_action":     []string{"deny"},
		"honeypot_remove":           []string{"/xmlrpc.php", "/stale"},
		"honeypot_default_action":   []string{"captcha_only"},
		"ban_duration":              []string{"0"},
		"ban_duration_override_set": []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyHoneypotFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.Honeypot.Extra) != 2 {
		t.Errorf("site scope must not touch baseline Extra; got %d rows", len(n.Honeypot.Extra))
	}
	ov, ok := n.Honeypot.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("Overrides[shop.example.com] missing")
	}
	if !reflect.DeepEqual(ov.AppendExtra, []string{"^/shop-trap"}) {
		t.Errorf("AppendExtra = %v", ov.AppendExtra)
	}
	if !reflect.DeepEqual(ov.AppendExtraAction, []string{"deny"}) {
		t.Errorf("AppendExtraAction = %v", ov.AppendExtraAction)
	}
	// Only "/xmlrpc.php" is in the default; "/stale" must be dropped.
	if !reflect.DeepEqual(ov.Remove, []string{"/xmlrpc.php"}) {
		t.Errorf("Remove = %v (stale /stale must be dropped)", ov.Remove)
	}
	if ov.DefaultAction != "captcha_only" {
		t.Errorf("DefaultAction = %q, want captcha_only", ov.DefaultAction)
	}
	if ov.BanDuration != 0 || !ov.BanDurationSet {
		t.Errorf("BanDuration = %d set=%t, want 0/true", ov.BanDuration, ov.BanDurationSet)
	}
}

func TestApplyHoneypotFormScopedSiteAllBlankDrops(t *testing.T) {
	n := &settings.Nginx{
		Honeypot: settings.HoneypotConfig{
			Extra: []string{"/wp-login.php"},
			Overrides: map[string]settings.HoneypotOverride{
				"shop.example.com": {AppendExtra: []string{"/old"}},
				"blog.example.com": {DefaultAction: "deny"},
			},
		},
	}
	body := url.Values{
		"honeypot_pat":            []string{""},
		"honeypot_default_action": []string{"inherit"},
	}
	r := formReq(t, body.Encode())
	if err := applyHoneypotFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.Honeypot.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank site scope must delete the override; map=%+v", n.Honeypot.Overrides)
	}
	if _, ok := n.Honeypot.Overrides["blog.example.com"]; !ok {
		t.Errorf("sibling override must survive")
	}
}

func TestApplyHoneypotFormScopedReset(t *testing.T) {
	n := &settings.Nginx{
		Honeypot: settings.HoneypotConfig{
			Overrides: map[string]settings.HoneypotOverride{
				"shop.example.com": {AppendExtra: []string{"/old"}},
				"blog.example.com": {DefaultAction: "deny"},
			},
		},
	}
	body := url.Values{
		"honeypot_pat":            []string{"^/will-be-ignored/"},
		"honeypot_default_action": []string{"deny"},
		"reset_honeypot":          []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyHoneypotFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.Honeypot.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", n.Honeypot.Overrides)
	}
	if _, ok := n.Honeypot.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides")
	}
}

// --- override counters ---

func TestChallengeOverrideCount(t *testing.T) {
	cases := []struct {
		name string
		ov   settings.ChallengeOverride
		want int
	}{
		{"empty", settings.ChallengeOverride{}, 0},
		{"theme only", settings.ChallengeOverride{Theme: "cat"}, 1},
		{"pow only", settings.ChallengeOverride{PowDifficulty: 22}, 1},
		{"credit set off", settings.ChallengeOverride{ShowCredit: false, ShowCreditSet: true}, 1},
		{"credit set on", settings.ChallengeOverride{ShowCredit: true, ShowCreditSet: true}, 1},
		{"credit unset", settings.ChallengeOverride{ShowCredit: true}, 0},
		{"all three", settings.ChallengeOverride{Theme: "cat", PowDifficulty: 20, ShowCreditSet: true}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := challengeOverrideCount(c.ov); got != c.want {
				t.Errorf("count = %d, want %d", got, c.want)
			}
		})
	}
}

func TestRateLimitOverrideCount(t *testing.T) {
	cases := []struct {
		name string
		ov   settings.RateLimitOverride
		want int
	}{
		{"empty", settings.RateLimitOverride{}, 0},
		{"rpm only", settings.RateLimitOverride{RequestsPerMin: 100}, 1},
		{"burst explicit 0", settings.RateLimitOverride{Burst: 0, BurstSet: true}, 1},
		{"burst inherit", settings.RateLimitOverride{Burst: 99}, 0},
		{"chMode + window", settings.RateLimitOverride{ChallengeMode: "deny", WindowSec: 30}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rateLimitOverrideCount(c.ov); got != c.want {
				t.Errorf("count = %d, want %d", got, c.want)
			}
		})
	}
}

func TestHoneypotOverrideCount(t *testing.T) {
	cases := []struct {
		name string
		ov   settings.HoneypotOverride
		want int
	}{
		{"empty", settings.HoneypotOverride{}, 0},
		{"append one", settings.HoneypotOverride{AppendExtra: []string{"/x"}}, 1},
		{"remove one", settings.HoneypotOverride{Remove: []string{"/y"}}, 1},
		{"default action", settings.HoneypotOverride{DefaultAction: "deny"}, 1},
		{"ban dur explicit 0", settings.HoneypotOverride{BanDuration: 0, BanDurationSet: true}, 1},
		{"ban dur inherit", settings.HoneypotOverride{BanDuration: 99}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := honeypotOverrideCount(c.ov); got != c.want {
				t.Errorf("count = %d, want %d", got, c.want)
			}
		})
	}
}
