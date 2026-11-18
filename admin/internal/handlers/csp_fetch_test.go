package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The admin's own pages say where they load from: this origin, a data: URL
// for an image, and for styles what the templates write inline.  The policy
// used to name scripts and frames alone, so an image, a stylesheet or a font
// that injected markup named could go to any origin, with what the page
// shows in its address.
func TestAdminCSPNamesWhereAPageLoadsFrom(t *testing.T) {
	h := newTestHandler(t)
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(h.AdminLoginGet)(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login page: %d", rr.Code)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for name, want := range map[string]string{
		"default-src": "default-src 'self'",
		"img-src":     "img-src 'self' data:",
		"style-src":   "style-src 'self' 'unsafe-inline'",
	} {
		if got := cspDirective(csp, name); got != want {
			t.Errorf("%s: %q, want %q (policy: %q)", name, got, want, csp)
		}
	}
	// No directive lets another origin in: every source is this origin, a
	// keyword, or one of the three things named above and in cspScriptSrc --
	// each in its own directive and nowhere else.  A scheme (https:), a
	// wildcard or a host name anywhere would be the hole the default closes.
	seen := map[string]bool{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) == 0 {
			t.Errorf("an empty directive in %q", csp)
			continue
		}
		name := f[0]
		if seen[name] {
			t.Errorf("%s is named twice in %q: a browser reads the first and drops the rest", name, csp)
		}
		seen[name] = true
		if name == "report-uri" {
			continue
		}
		for _, src := range f[1:] {
			switch {
			case src == "'self'", src == "'none'":
			case src == "data:" && name == "img-src":
			case src == "'unsafe-inline'" && name == "style-src":
			case strings.HasPrefix(src, "'nonce-") && name == "script-src":
			case src == "'report-sample'" && name == "script-src":
			default:
				t.Errorf("%s names %s (policy: %q)", name, src, csp)
			}
		}
	}
	for _, name := range []string{"default-src", "script-src", "object-src", "base-uri", "form-action", "frame-ancestors"} {
		if !seen[name] {
			t.Errorf("the policy has no %s: %q", name, csp)
		}
	}
	// The wizard, which sits outside both gates, carries the same.
	rr = httptest.NewRecorder()
	h.AdminHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(
		rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/", nil))
	if got := cspDirective(rr.Header().Get("Content-Security-Policy"), "default-src"); got != "default-src 'self'" {
		t.Errorf("the wizard's policy: default-src = %q", got)
	}
	// A page on an admin route that is not the admin's keeps the framing
	// rules and takes none of this: it loads what its own operator gave it
	// (a logo, a CAPTCHA provider's script).
	rr = httptest.NewRecorder()
	rr.Header().Set("Content-Security-Policy", adminCSP("n0nce", "/unmask"))
	keepAdminCSPWithoutScripts(rr)
	if got := rr.Header().Get("Content-Security-Policy"); got != adminCSPBase || strings.Contains(got, "default-src") {
		t.Errorf("a page that is not the admin's: policy %q, want %q", got, adminCSPBase)
	}
}

// loadTagRE: a start tag of an element that loads something when the page is
// read -- as markup, or inside an HTML string a script builds.
var loadTagRE = regexp.MustCompile(`(?is)<(img|link|script|iframe|frame|source|audio|video|embed|object|track|input)\b[^>]*>`)

// loadAttrRE: the attribute of such a tag that names what is loaded.
var loadAttrRE = regexp.MustCompile(`(?is)\b(src|href|data|poster|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// The shipped templates load nothing the policy refuses: no tag that fetches
// (an image, a stylesheet, a frame, a script file, media) names another
// origin.  The browser refuses such a load without a word on the page -- an
// image is simply not there -- so a template that came to name one would
// look fine in review and broken in use.  Links are not loads: an <a> may
// point anywhere.
func TestAdminTemplatesLoadFromThisOriginOnly(t *testing.T) {
	templates, _ := cspAssets(t)
	names := make([]string, 0, len(templates))
	for name := range templates {
		names = append(names, name)
	}
	sort.Strings(names)
	tags := 0
	for _, name := range names {
		for _, tag := range loadTagRE.FindAllString(templates[name], -1) {
			tags++
			for _, m := range loadAttrRE.FindAllStringSubmatch(tag, -1) {
				v := strings.TrimSpace(m[2] + m[3])
				lower := strings.ToLower(v)
				if strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") || strings.HasPrefix(lower, "//") ||
					strings.HasPrefix(lower, "blob:") || strings.HasPrefix(lower, "ws:") || strings.HasPrefix(lower, "wss:") {
					t.Errorf("%s: %s loads from another origin (%s=%q); the admin's policy is default-src 'self'", name, strings.Join(strings.Fields(tag), " "), m[1], v)
				}
			}
		}
	}
	if tags < 60 {
		t.Errorf("read %d loading tags in %d templates: the scan no longer sees them", tags, len(names))
	}
	// The scan itself: what it has to catch.
	for _, bad := range []string{
		`<img src="https://cdn.example/x.png">`,
		`<link rel="stylesheet" href="//fonts.example/css">`,
		`<IFRAME SRC='http://other.example/'></IFRAME>`,
		`<script src="https://cdn.example/a.js"></script>`,
	} {
		caught := false
		for _, tag := range loadTagRE.FindAllString(bad, -1) {
			for _, m := range loadAttrRE.FindAllStringSubmatch(tag, -1) {
				v := strings.ToLower(m[2] + m[3])
				if strings.HasPrefix(v, "http:") || strings.HasPrefix(v, "https:") || strings.HasPrefix(v, "//") {
					caught = true
				}
			}
		}
		if !caught {
			t.Errorf("the scan does not catch %s", bad)
		}
	}
}
