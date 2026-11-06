package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The routes under /admin/test/ serve, behind the session, pages that are
// not the admin's templates: the challenge page, the deny page, and the
// test index a Go string builds.  The session gate puts the admin's policy
// on every response; these tests pin what each of them ends up with.

// asSignedIn runs fn behind AuthMiddleware with a superadmin's session.
func asSignedIn(h *Handler, fn http.HandlerFunc, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	req.AddCookie(issueSessionCookie(h.adminSecret(), "/unmask", 1, "superadmin", false, false, 0))
	rr := httptest.NewRecorder()
	h.AuthMiddleware(fn)(rr, req)
	return rr
}

// The challenge page keeps its own policy on the admin's test routes: its
// nonce on its scripts, its worker, and nothing of the admin's -- which
// names a nonce the challenge page's scripts do not carry.
func TestChallengeOnAdminTestRouteKeepsItsOwnPolicy(t *testing.T) {
	h := installedHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Server.BasePath = "/unmask"
		s.Secret.CaptchaSecretBase = "test-base"
	})
	for path, fn := range map[string]http.HandlerFunc{
		"/unmask/admin/test/force-pow":              h.ForcePoW,
		"/unmask/admin/test/force-captcha":          h.ForceCaptcha,
		"/unmask/admin/test/force-pow-then-captcha": h.ForcePoWThenCaptcha,
	} {
		rr := asSignedIn(h, fn, path)
		csp := rr.Header().Get("Content-Security-Policy")
		m := nonceInHeaderRE.FindStringSubmatch(csp)
		if m == nil || !strings.HasPrefix(csp, "default-src 'self'; script-src 'self' 'nonce-") || !strings.Contains(csp, "worker-src blob:") {
			t.Fatalf("%s: policy = %q, want the challenge page's", path, csp)
		}
		if strings.Contains(csp, "frame-ancestors") || strings.Contains(csp, "report-uri") || strings.Contains(csp, "report-sample") {
			t.Errorf("%s: the admin's policy leaked into the challenge page's: %s", path, csp)
		}
		if n := strings.Count(rr.Body.String(), `<script nonce="`+m[1]+`">`); n != 3 {
			t.Errorf("%s: %d script tags carry the policy's nonce, want 3", path, n)
		}
		if rr.Header().Get("Content-Security-Policy-Report-Only") != "" {
			t.Errorf("%s: a report-only policy rides the challenge page", path)
		}
	}
}

// An operator's copy of the challenge page from before the nonce carries no
// nonce to name.  Previewed on the admin's test route it keeps the part of
// the admin's policy that needs none, as it did before the admin had a
// script directive, and its scripts run; on the public route it has no
// policy at all.
func TestOldChallengePageOnAdminTestRouteRunsItsScripts(t *testing.T) {
	h := installedHandler(t)
	dir := t.TempDir()
	old := strings.ReplaceAll(string(mustRead(t, "../../assets/static/challenge.html")), ` nonce="`+nonceAttrPlaceholder+`"`, "")
	if err := os.WriteFile(filepath.Join(dir, "challenge.html"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Server.BasePath = "/unmask"
		s.Secret.CaptchaSecretBase = "test-base"
		s.Challenge.Default.ChallengeHTMLPath = filepath.Join(dir, "challenge.html")
	})
	rr := asSignedIn(h, h.ForcePoW, "/unmask/admin/test/force-pow")
	if !strings.Contains(rr.Body.String(), "<script>") {
		t.Fatal("the operator's page was not served; the test checks nothing")
	}
	if got := rr.Header().Get("Content-Security-Policy"); got != adminCSPBase {
		t.Errorf("policy on the admin route = %q, want %q", got, adminCSPBase)
	}
	// The same page on the public route: no policy, as before.
	pub := httptest.NewRecorder()
	h.ForcePoW(pub, httptest.NewRequest(http.MethodGet, "/unmask/test/force-pow", nil))
	if got := pub.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("policy on the public route = %q, want none", got)
	}
}

// The test index is a page of the admin's own on the admin route, under the
// admin's policy: its one script carries the response's nonce.  On the
// public route there is no policy and no nonce.
func TestTestIndexScriptCarriesTheAdminNonce(t *testing.T) {
	h := installedHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	rr := asSignedIn(h, h.TestIndex, "/unmask/admin/test/")
	csp := rr.Header().Get("Content-Security-Policy")
	m := nonceInHeaderRE.FindStringSubmatch(csp)
	if m == nil || cspDirective(csp, "script-src") == "" {
		t.Fatalf("policy = %q, want the admin's with a nonce", csp)
	}
	tags := scriptTagRE.FindAllString(rr.Body.String(), -1)
	if len(tags) != 1 || tags[0] != `<script nonce="`+m[1]+`">` {
		t.Errorf("script tags = %q, want one with the nonce %s", tags, m[1])
	}

	pub := httptest.NewRecorder()
	h.TestIndex(pub, httptest.NewRequest(http.MethodGet, "/unmask/test/", nil))
	if tags := scriptTagRE.FindAllString(pub.Body.String(), -1); len(tags) != 1 || tags[0] != "<script>" {
		t.Errorf("public route: script tags = %q, want the bare one", tags)
	}
	if got := pub.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("public route: policy = %q, want none", got)
	}
}

// The deny preview is framed by the settings page and is the deny page as
// nginx serves it, with a script that carries no nonce: it relaxes framing
// to this origin and takes no script directive.
func TestRateDenyPreviewKeepsItsRelaxedPolicy(t *testing.T) {
	h := installedHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Server.BasePath = "/unmask" })
	for _, path := range []string{"/unmask/admin/test/rate-deny", "/unmask/admin/test/rate-deny?kind=ban"} {
		rr := asSignedIn(h, h.PreviewRateDeny, path)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rr.Code)
		}
		if got := rr.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'" {
			t.Errorf("%s: policy = %q", path, got)
		}
		if got := rr.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("%s: X-Frame-Options = %q", path, got)
		}
		if rr.Header().Get("Content-Security-Policy-Report-Only") != "" {
			t.Errorf("%s: a report-only policy rides the preview", path)
		}
	}
}
