package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// Every route under {base}/admin/ is authorised the same way: no session
// means the login page (or 401 / 403), and a viewer may read but never
// write.  These tests take the routes from the router buildRouter builds --
// a route added without AuthMiddleware, or a write without RequireRole,
// fails here rather than in production -- and drive each one through the
// real middleware chain with a real viewer session.

// adminRoute: one registered pattern, resolved to a request.
type adminRoute struct {
	pattern string // as registered, "POST /unmask/admin/settings/save"
	method  string
	path    string // the pattern with its wildcards filled in
}

// routePatterns lists the patterns registered on mux.  net/http keeps no
// public list, so this walks the ServeMux's routing tree by reflection:
// every node with a pattern is a registered route.  A Go release that moves
// those fields fails the walk loudly (t.Fatal), not silently with an empty
// list -- and the callers check the count against known routes as well.
func routePatterns(t *testing.T, mux *http.ServeMux) []string {
	t.Helper()
	var out []string
	var walk func(node reflect.Value)
	walk = func(node reflect.Value) {
		p := node.FieldByName("pattern")
		if !p.IsValid() {
			t.Fatal("net/http.ServeMux's routing node has no pattern field; update routePatterns for this Go release")
		}
		if !p.IsNil() {
			out = append(out, p.Elem().FieldByName("str").String())
		}
		children := node.FieldByName("children")
		if s := children.FieldByName("s"); s.IsValid() {
			for i := 0; i < s.Len(); i++ {
				walk(s.Index(i).FieldByName("value").Elem())
			}
		}
		if m := children.FieldByName("m"); m.IsValid() && !m.IsNil() {
			for it := m.MapRange(); it.Next(); {
				walk(it.Value().Elem())
			}
		}
		for _, name := range []string{"multiChild", "emptyChild"} {
			if c := node.FieldByName(name); c.IsValid() && !c.IsNil() {
				walk(c.Elem())
			}
		}
	}
	tree := reflect.ValueOf(mux).Elem().FieldByName("tree")
	if !tree.IsValid() {
		t.Fatal("net/http.ServeMux has no tree field; update routePatterns for this Go release")
	}
	walk(tree)
	sort.Strings(out)
	return out
}

var wildcardRE = regexp.MustCompile(`\{[^}]*\}`)

// adminRoutes: the routes under base/admin/, each with a concrete path.
func adminRoutes(t *testing.T, mux *http.ServeMux, base string) []adminRoute {
	t.Helper()
	fill := map[string]string{"{$}": "", "{tab}": "sites", "{site}": "example.test", "{id}": "1"}
	var out []adminRoute
	for _, pat := range routePatterns(t, mux) {
		method, path := "", pat
		if i := strings.IndexByte(pat, ' '); i > 0 {
			method, path = pat[:i], pat[i+1:]
		}
		if !strings.HasPrefix(path, base+"/admin/") {
			continue
		}
		path = wildcardRE.ReplaceAllStringFunc(path, func(w string) string {
			if v, ok := fill[w]; ok {
				return v
			}
			return "1"
		})
		if method == "" {
			// A route registered for every method: the two that matter here.
			out = append(out, adminRoute{pat, http.MethodGet, path}, adminRoute{pat, http.MethodPost, path})
			continue
		}
		out = append(out, adminRoute{pat, method, path})
	}
	if len(out) < 90 {
		t.Fatalf("only %d admin routes found; the walk missed some (%v)", len(out), out)
	}
	for _, want := range []string{"GET " + base + "/admin/{$}", "POST " + base + "/admin/settings/save", "DELETE " + base + "/admin/api/community-bans/vote/{id}"} {
		found := false
		for _, r := range out {
			found = found || r.pattern == want
		}
		if !found {
			t.Fatalf("the walk did not find %q", want)
		}
	}
	return out
}

// Routes that are not behind the session on purpose.
var adminRoutesWithoutSession = []string{
	"/admin/login",           // the sign-in itself
	"/admin/forgot-password", // the reset mail
	"/admin/reset-password",  // the reset link
	"/admin/setup/",          // the wizard: the setup token / SetupGate
	"/admin/csp-report",      // the browser's own post: the login page reports too, and no token rides it
}

// Writes a viewer may make.
var adminWritesOpenToViewer = map[string]string{
	"/admin/logout":              "signing out needs no role (CSRF only)",
	"/admin/profile/save":        "the account's own profile",
	"/admin/api/playground/eval": "an evaluation: the POST carries the input and changes nothing",
}

// Reads a viewer may make that do not return: the event stream is served
// until the client goes away.
var adminReadsThatStream = map[string]string{
	"/admin/api/events/stream": "server-sent events",
}

func routeListed(list []string, base, path string) bool {
	for _, p := range list {
		if strings.HasPrefix(path, base+p) {
			return true
		}
	}
	return false
}

// routeFixture: a migrated SQLite with a viewer account, a handler on it and
// the router.  The setup token is pointed at a directory of its own so a
// token on this host cannot send every request to the wizard.
func routeFixture(t *testing.T) (settings.Settings, *handlers.Handler, *http.ServeMux) {
	t.Helper()
	config, database := migrateConfig(t, "")
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: database})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(config)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = filepath.Join(t.TempDir(), "nginx")
	// The hub, pointed at a dead port: no route here may reach unmask.sh.
	s.CommunityBans.RegisterURL = "http://127.0.0.1:9/register"
	s.CommunityBans.SubmitURL = "http://127.0.0.1:9/submit"
	s.CommunityBans.FeedURL = "http://127.0.0.1:9/list.json"
	s.CommunityBans.AggregateURL = "http://127.0.0.1:9/aggregate"
	repo := user.New(d)
	if _, err := repo.Create(context.Background(), "viewer", "viewer-pass-2026", user.RoleViewer); err != nil {
		t.Fatal(err)
	}
	h := &handlers.Handler{DB: d, UserRepo: repo, ConfigPath: config, Version: "0.0.0", HostID: "routes-test"}
	h.SetSettings(s)
	handlers.SetSetupTokenDir(t.TempDir())
	_ = os.Remove(handlers.SetupTokenPath)
	return s, h, buildRouter(s, h)
}

// serve runs one request through the router with a deadline, so a handler
// that waits for a client that never goes away cannot hang the test.
func serve(mux *http.ServeMux, req *http.Request) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

// viewerLogin signs the viewer in through the real login route and returns
// the session and CSRF cookies.
func viewerLogin(t *testing.T, mux *http.ServeMux, base string) []*http.Cookie {
	t.Helper()
	return loginAs(t, mux, base, "viewer", "viewer-pass-2026")
}

// loginAs signs an account in through the real login route and returns the
// session and CSRF cookies.
func loginAs(t *testing.T, mux *http.ServeMux, base, name, password string) []*http.Cookie {
	t.Helper()
	// The form first: its GET sets the nonce cookie and embeds the token the
	// POST must carry (the sign-in has its own CSRF check since 0.1.54).
	get := serve(mux, httptest.NewRequest(http.MethodGet, base+"/admin/login", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("login form: %d", get.Code)
	}
	m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatalf("login form carries no _csrf token")
	}
	form := url.Values{"username": {name}, "password": {password}, "_csrf": {m[1]}}
	req := httptest.NewRequest(http.MethodPost, base+"/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range get.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := serve(mux, req)
	if rec.Code != http.StatusFound || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("%s login: %d %s", name, rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	var session, csrf bool
	for _, c := range cookies {
		session = session || (c.Name == "unmask_admin_session" && c.Value != "")
		csrf = csrf || (c.Name == "unmask_admin_csrf" && c.Value != "")
	}
	if !session || !csrf {
		t.Fatalf("login issued no session + CSRF cookie pair: %v", cookies)
	}
	return cookies
}

// TestAdminRoutesRefuseWithoutSession: every admin route, requested with no
// cookie at all, sends the visitor to the login page or answers 401 / 403.
func TestAdminRoutesRefuseWithoutSession(t *testing.T) {
	s, _, mux := routeFixture(t)
	base := s.Server.BasePath
	for _, r := range adminRoutes(t, mux, base) {
		if routeListed(adminRoutesWithoutSession, base, r.path) {
			continue
		}
		req := httptest.NewRequest(r.method, r.path, nil)
		rec := serve(mux, req)
		loc := rec.Header().Get("Location")
		switch {
		case rec.Code == http.StatusFound && strings.Contains(loc, base+"/admin/login"):
		case rec.Code == http.StatusUnauthorized, rec.Code == http.StatusForbidden:
		default:
			t.Errorf("%s: without a session got %d (Location %q), want the login page, 401 or 403", r.pattern, rec.Code, loc)
		}
	}
}

// TestAdminRoutesViewerCannotWrite: with a viewer's session (and its CSRF
// token, so the refusal is the role's), every POST / PUT / PATCH / DELETE
// under /admin/ is 403, except the writes a viewer may make; and no read is
// bounced to the login page or breaks on the server.
func TestAdminRoutesViewerCannotWrite(t *testing.T) {
	s, _, mux := routeFixture(t)
	base := s.Server.BasePath
	cookies := viewerLogin(t, mux, base)
	csrf := ""
	for _, c := range cookies {
		if c.Name == "unmask_admin_csrf" {
			csrf = c.Value
		}
	}
	for _, r := range adminRoutes(t, mux, base) {
		if routeListed(adminRoutesWithoutSession, base, r.path) {
			continue
		}
		req := httptest.NewRequest(r.method, r.path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrf)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		write := r.method != http.MethodGet && r.method != http.MethodHead
		if write {
			if _, open := adminWritesOpenToViewer[strings.TrimPrefix(r.path, base)]; open {
				continue
			}
			rec := serve(mux, req)
			body := rec.Body.String()
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: a viewer got %d, want 403", r.pattern, rec.Code)
			} else if strings.Contains(strings.ToLower(body), "csrf") {
				t.Errorf("%s: the 403 is the CSRF check's, not the role's: %q", r.pattern, body)
			}
			continue
		}
		if _, streams := adminReadsThatStream[strings.TrimPrefix(r.path, base)]; streams {
			continue
		}
		// A read may answer 502 / 503 here: the hub proxies have no token in
		// this fixture and say so.  500 is a handler that broke.
		rec := serve(mux, req)
		loc := rec.Header().Get("Location")
		if rec.Code == http.StatusInternalServerError || (rec.Code == http.StatusFound && strings.Contains(loc, base+"/admin/login")) {
			t.Errorf("%s: a viewer's read got %d (Location %q)", r.pattern, rec.Code, loc)
		}
	}
}

// TestCrawlersCSVUnderTheStatsGate: the crawler CSV is the statistics page's
// data as a file, and is gated as the page is.  Without a session it sends
// the visitor to the login page like the page does; a viewer, who may open
// the page, gets the file.  A route moved under a stricter gate, or left out
// of the router, fails here.
func TestCrawlersCSVUnderTheStatsGate(t *testing.T) {
	s, _, mux := routeFixture(t)
	base := s.Server.BasePath
	const page, file = "/admin/stats/", "/admin/stats/crawlers.csv?range=7d"
	for _, path := range []string{page, file} {
		rec := serve(mux, httptest.NewRequest(http.MethodGet, base+path, nil))
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.Contains(loc, base+"/admin/login") {
			t.Errorf("%s without a session: %d (Location %q), want the login page", path, rec.Code, loc)
		}
		if strings.Contains(rec.Body.String(), "date,site,category") {
			t.Errorf("%s without a session: the file was served", path)
		}
	}
	cookies := viewerLogin(t, mux, base)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, base+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return serve(mux, req)
	}
	if rec := get(page); rec.Code != http.StatusOK {
		t.Fatalf("%s as a viewer: %d, want 200", page, rec.Code)
	}
	rec := get(file)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s as a viewer: %d, want 200 -- the page it belongs to opens for the role", file, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("%s as a viewer: Content-Type %q", file, ct)
	}
	if body := rec.Body.String(); !strings.HasPrefix(body, "date,site,category,crawler,total,challenged,passed,verified,named_pass,range_published\n") {
		t.Errorf("%s as a viewer: body starts %.80q, want the header row", file, body)
	}
	// A write to it is not a route at all.
	req := httptest.NewRequest(http.MethodPost, base+"/admin/stats/crawlers.csv", strings.NewReader(""))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if rec := serve(mux, req); rec.Code == http.StatusOK {
		t.Errorf("POST to the CSV answered %d", rec.Code)
	}
}
