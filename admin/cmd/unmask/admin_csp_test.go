package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/banfile"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The admin's Content-Security-Policy runs a script only when its tag
// carries the nonce the response's header names (handlers/csp_nonce.go).
// The header is the middleware's and the tag is a template's, so the two can
// drift apart without either being wrong on its own: a route that skips the
// middleware, a handler that leaves the nonce out of its page data, a
// partial that reads it off the wrong dot.  These tests take every page the
// router serves, through the real chain with a real session, and hold each
// response to its own header.

var (
	cspNonceRE     = regexp.MustCompile(`script-src 'self' 'nonce-([A-Za-z0-9+/=]{22,})'`)
	settingsTabRE  = regexp.MustCompile(`href="(/unmask/admin/settings/[a-z0-9-]+/)"`)
	scriptNonceRE  = regexp.MustCompile(`\snonce="([^"]*)"`)
	adminPolicyFmt = "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'; script-src 'self' 'nonce-%s' 'report-sample'; report-uri /unmask/admin/csp-report"
)

// scriptTags returns the start tag of every script element in a page.  What
// a script's own text says ("<script" in a string) is not a tag: the text is
// skipped to the element's end.
func scriptTags(body string) []string {
	var out []string
	low := strings.ToLower(body)
	for i := 0; ; {
		j := strings.Index(low[i:], "<script")
		if j < 0 {
			return out
		}
		i += j
		end := strings.IndexByte(body[i:], '>')
		if end < 0 {
			return append(out, body[i:])
		}
		out = append(out, body[i:i+end+1])
		i += end + 1
		if k := strings.Index(low[i:], "</script"); k >= 0 {
			i += k
		}
	}
}

func TestAdminPagesCarryTheNonceOfTheirPolicy(t *testing.T) {
	s, h, mux := routeFixture(t)
	base := s.Server.BasePath
	if _, err := h.UserRepo.Create(context.Background(), "root", "root-pass-2026", user.RoleSuperadmin); err != nil {
		t.Fatal(err)
	}
	// The two tabs behind the Advanced switch; and one of the notices that
	// render inside a {{ with }}, where the nonce has to come off $: the bar
	// that says nginx cannot read the ban list, on every signed-in page.
	s.Nginx.AdvancedEnabled = true
	s.Nginx.Honeypot.BanFilePath = filepath.Join(t.TempDir(), "banned.txt")
	h.SetSettings(s)
	h.BanFileCheck = func() banfile.Verdict {
		return banfile.Verdict{User: "nginx", Source: "nginx.conf", Blocker: "/var/lib/unmask", Need: "x"}
	}
	cookies := loginAs(t, mux, base, "root", "root-pass-2026")
	get := func(path string, signedIn bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if signedIn {
			for _, c := range cookies {
				req.AddCookie(c)
			}
		}
		return serve(mux, req)
	}

	// Every GET route, the settings tabs each, a site's scope on the two
	// tabs that take one, and the pages before a session.
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for _, r := range adminRoutes(t, mux, base) {
		if _, streams := adminReadsThatStream[strings.TrimPrefix(r.path, base)]; r.method == http.MethodGet && !streams {
			add(r.path)
		}
	}
	nav := get(base+"/admin/settings/", true).Body.String()
	for _, m := range settingsTabRE.FindAllStringSubmatch(nav, -1) {
		add(m[1])
	}
	for _, tab := range []string{"web-bot-auth", "privacy-pass", "theme", "challenge", "ua-filter", "network", "rate-limit"} {
		if !seen[base+"/admin/settings/"+tab+"/"] {
			t.Fatalf("the settings nav does not link the %s tab; the walk would miss it", tab)
		}
	}
	add(base + "/admin/settings/challenge/?scope=shop.example.test")
	add(base + "/admin/settings/theme/?scope=shop.example.test")

	pages, withNotice := 0, 0
	check := func(p string, signedIn bool) {
		rec := get(p, signedIn)
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			return // JSON, a download, an image, a plain-text refusal
		}
		who := "signed in"
		if !signedIn {
			who = "no session"
		}
		csp := rec.Header().Get("Content-Security-Policy")
		body := rec.Body.String()
		rel := strings.TrimPrefix(p, base)
		if ro := rec.Header().Get("Content-Security-Policy-Report-Only"); ro != "" {
			t.Errorf("%s (%s): a report-only policy is still sent: %s", p, who, ro)
		}
		// Two routes serve a page that is not the admin's, under that
		// page's rules: the deny page as nginx serves it (framed by the
		// settings page, with a script of its own), and the challenge page
		// (its own policy, with its own nonce).
		if strings.HasPrefix(rel, "/admin/test/rate-deny") {
			if csp != "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'" {
				t.Errorf("%s: the deny preview's policy changed: %s", p, csp)
			}
			return
		}
		m := cspNonceRE.FindStringSubmatch(csp)
		if m == nil {
			t.Errorf("%s (%s): an HTML response without a nonce in its policy: %q", p, who, csp)
			return
		}
		if strings.HasPrefix(rel, "/admin/test/force-") {
			if !strings.HasPrefix(csp, "default-src 'self'; script-src 'self' 'nonce-") || strings.Contains(csp, "frame-ancestors") || strings.Contains(csp, "report-uri") {
				t.Errorf("%s: the challenge page's policy on the admin route: %s", p, csp)
			}
		} else if want := strings.Replace(adminPolicyFmt, "%s", m[1], 1); csp != want {
			t.Errorf("%s (%s): policy\n got %s\nwant %s", p, who, csp, want)
		}
		tags := scriptTags(body)
		for _, tag := range tags {
			if n := scriptNonceRE.FindStringSubmatch(tag); n == nil || n[1] != m[1] {
				t.Errorf("%s (%s): %s does not carry the response's nonce %s", p, who, tag, m[1])
			}
		}
		if len(tags) > 0 {
			pages++
		}
		if strings.Contains(body, `id="bfnote"`) {
			withNotice++
		}
	}
	for _, p := range paths {
		check(p, true)
	}
	for _, p := range []string{"/admin/login", "/admin/forgot-password", "/admin/reset-password?token=not-a-token"} {
		check(base+p, false)
	}
	// The walk is only worth its name if it rendered the pages: the settings
	// tabs alone are more than twenty.
	if pages < 45 {
		t.Errorf("only %d responses carried a script; the walk did not render the pages", pages)
	}
	if withNotice < 20 {
		t.Errorf("the ban-list notice was on %d pages; its script, inside a {{ with }}, went unchecked", withNotice)
	}
}
