package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// faAdminCfg: a stock forward-auth install.  The shipped "unmask itself"
// preset gates /unmask/admin/, no mode is pinned anywhere (so it follows the
// tab default, which ends in a CAPTCHA), and browsers get a PoW-only screen --
// which is what a default install looks like.
func faAdminCfg() settings.Settings {
	var s settings.Settings
	s.Nginx.ProtectedPaths.EnabledPresets = []string{"unmask"}
	s.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	s.RateLimit.Default.ChallengeMode = settings.RateChallengePoWOnly
	return s
}

// The challenge served for a protected path must be able to satisfy the gate
// that protected path imposes.
//
// On forward-auth the challenge arrives as a plain internal redirect: no
// X-Protected-Mode header, and the URI the visitor actually asked for survives
// only in X-Original-URI.  The serve used to discard that header whenever it
// pointed under the unmask mount -- which is exactly where the shipped preset
// points -- so it never learned the request was protected and handed out the
// UA axis's PoW-only screen, while the check went on demanding a CAPTCHA-grade
// pass.  The visitor solved the PoW, was refused for holding a "pow" credential
// and was served the same screen again, forever.
func TestForwardAuthProtectedAdminServesASatisfiableChain(t *testing.T) {
	h := newTestHandler(t)
	h.SetSettings(faAdminCfg())

	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	// What fa-nginx forwards for `error_page 401 = /unmask/challenge/;`.
	req.Header.Set("X-Original-URI", "/unmask/admin/")
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)
	body := rr.Body.String()

	chMode := chModeFromChallengeHTML(body)
	if chMode == "" {
		t.Fatalf("could not read the chain out of the served challenge (status %d)", rr.Code)
	}
	if !chainEndsInCaptcha(chMode) {
		t.Errorf("served chain %q cannot mint the CAPTCHA-grade pass the protected path demands "+
			"-- the visitor would solve it and be refused, forever", chMode)
	}

	// And the gate really does demand one, so the assertion above is not
	// passing because nothing was required.
	if !requestNeedsCaptchaGrade(req.Header.Get("User-Agent"), "/unmask/admin/", "", h.snapshotSettings()) {
		t.Error("precondition: /unmask/admin/ should require a CAPTCHA-grade pass on this config")
	}
	// The mode itself must resolve, so the serve reports "protected" rather
	// than falling through to an unexplained challenge.
	if m := protectedModeForOrig(h.cfg().Nginx, "", "/unmask/admin/"); !nginxconf.ModeEndsInCaptcha(m) {
		t.Errorf("protected mode for /unmask/admin/ = %q, want a captcha-ending mode", m)
	}
}

// The backstop, independent of how the chain was picked: even when the check
// hands the serve an explicit chm= that cannot satisfy the gate, the serve must
// not hand it out.
func TestServeChallengeNeverServesAnUnsatisfiableChain(t *testing.T) {
	h := newTestHandler(t)
	h.SetSettings(faAdminCfg())

	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?chm=pow_only", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	req.Header.Set("X-Original-URI", "/unmask/admin/")
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)

	if got := chModeFromChallengeHTML(rr.Body.String()); !chainEndsInCaptcha(got) {
		t.Errorf("an explicit chm=pow_only was served for a captcha-graded path (got %q)", got)
	}
}

// A path with no CAPTCHA-grade requirement keeps the light screen: the guard
// must not escalate everyone.
func TestServeChallengeKeepsThePoWScreenWhenNoGradeIsRequired(t *testing.T) {
	h := newTestHandler(t)
	h.SetSettings(faAdminCfg())

	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	req.Header.Set("X-Original-URI", "/some/ordinary/page/")
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)

	if got := chModeFromChallengeHTML(rr.Body.String()); got != settings.RateChallengePoWOnly {
		t.Errorf("an unprotected path should keep the PoW-only screen, got %q", got)
	}
}

// The challenge endpoints themselves must never resolve to a protected rule
// about themselves (a direct hit carries them in X-Original-URI).
func TestProtectedOrigURIExcludesTheUnmaskEndpoints(t *testing.T) {
	for _, uri := range []string{
		"/unmask/challenge/", "/unmask/challenge.html", "/unmask/api/check",
		"/unmask/static/challenge.js", "/unmask/_deny",
	} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
		req.Header.Set("X-Original-URI", uri)
		if got := protectedOrigURI(req, "/unmask"); got != "" {
			t.Errorf("X-Original-URI %q should not resolve as a protected URI, got %q", uri, got)
		}
	}
	// ...but the admin, which the shipped preset exists to gate, must survive.
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("X-Original-URI", "/unmask/admin/settings/")
	if got := protectedOrigURI(req, "/unmask"); got != "/unmask/admin/settings/" {
		t.Errorf("the admin URI was dropped: got %q", got)
	}
}

// chModeFromChallengeHTML pulls the chain the served page will run out of the
// placeholder ServeChallenge substitutes.
func chModeFromChallengeHTML(body string) string {
	const marker = `/*__CHMODE__*/"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// The shipped defaults must not lock a new operator out of their own admin.
//
// This is the configuration a first install actually runs: the "unmask itself"
// preset ON, no mode pinned anywhere (so the tab default, which ends in a
// CAPTCHA), and known browsers on a PoW-only screen.  On nginx forward-auth
// the challenge arrives with the URI only in X-Original-URI, so every input to
// this decision is a shipped default -- nobody has to misconfigure anything to
// reach it.  The first thing a new user does is open the admin, so a loop here
// is the first thing they would ever see.
//
// Reading the settings through Load() rather than building a struct is the
// point: it is defaults() that has to be safe, not a config a test invented.
func TestFreshInstallDoesNotLockTheOperatorOutOnForwardAuth(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(empty, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(empty) // = defaults()
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(s)

	// Guard the premise: if a later release changes these, this test should
	// say so rather than quietly stop covering the case it was written for.
	if len(s.Nginx.ProtectedPaths.EnabledPresets) == 0 {
		t.Fatal("premise: the shipped protected preset is no longer on by default")
	}
	if s.Global.KnownBrowserAction != settings.RateChallengePoWOnly {
		t.Logf("note: known_browser_action default is now %q", s.Global.KnownBrowserAction)
	}

	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Original-URI", "/unmask/admin/")
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)

	served := chModeFromChallengeHTML(rr.Body.String())
	if !requestNeedsCaptchaGrade(ua, "/unmask/admin/", "", h.snapshotSettings()) {
		t.Fatal("premise: the shipped admin gate no longer requires a CAPTCHA-grade pass")
	}
	if !chainEndsInCaptcha(served) {
		t.Errorf("a fresh install serves %q for its own admin while demanding a CAPTCHA-grade pass "+
			"-- the operator solves it, is refused, and is served it again, forever", served)
	}
}
