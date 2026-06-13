package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// newTestHandler builds a Handler backed by a temporary sqlite file.
// Inlines CREATE TABLE so the schema lives in a single file.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	dbcfg := settings.DB{
		Driver:     "sqlite",
		SQLitePath: filepath.Join(dir, "test.sqlite"),
	}
	conn, err := db.Open(dbcfg)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	const schema = `
        CREATE TABLE unmask_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site VARCHAR(64) NOT NULL DEFAULT 'default',
            host VARCHAR(64),
            ip_address BLOB NOT NULL,
            user_agent VARCHAR(255),
            ja4 VARCHAR(40),
            ja4_verdict VARCHAR(40),
            ja4_verdict_id INTEGER,
            phase VARCHAR(16) NOT NULL,
            flags INTEGER NOT NULL DEFAULT 0,
            reload_count INTEGER NOT NULL DEFAULT 0,
            cookie_bv VARCHAR(80),
            cookie_br VARCHAR(8),
            payload_json TEXT,
            scheme VARCHAR(8) NOT NULL DEFAULT '',
            port INTEGER NOT NULL DEFAULT 0,
            date_created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX idx_e_phase ON unmask_event(phase, date_created);
        CREATE INDEX idx_e_site ON unmask_event(site, date_created);
    `
	for _, stmt := range strings.Split(schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("schema: %v\n%s", err, stmt)
		}
	}
	s := settings.Settings{
		Secret: settings.Secret{
			BVSecret:          "test-secret",
			CaptchaSecretBase: "test-base",
		},
		Challenge: settings.ChallengeConfig{
			Default: settings.ChallengeValues{
				PowCookieValidSeconds: 86400 * 7,
				DebugRateLimitPer5Min: 100,
				CaptchaProvider: settings.Captcha{
					Provider:              "builtin",
					BuiltinScoreThreshold: 0.5,
				},
			},
		},
	}
	h := &Handler{DB: conn}
	h.SetSettings(s)
	return h
}

// VerifyJSON: high score → 200 ok=1 + Set-Cookie _bv.
func TestVerifyJSON_BehavioralPass(t *testing.T) {
	h := newTestHandler(t)
	// ct = the server-issued proof-of-load token, bound to the client IP and
	// CaptchaSecretBase (= "test-base" in newTestHandler).  Required since the
	// behavioral path now rejects a blind POST with no/invalid ct.
	ct := captcha.IssueToken("test-base", "1.2.3.4")
	body := `{"token":"x","ct":"` + ct + `","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("X-Client-JA4", "t13d1517h2_aaa_bbb")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	var bv string
	for _, c := range cookies {
		if c.Name == "_bv" {
			bv = c.Value
		}
	}
	if bv == "" {
		t.Fatal("expected _bv cookie, none set")
	}
	if !strings.HasSuffix(bv, ".captcha") {
		t.Errorf("cookie kind suffix mismatch: %q", bv)
	}

	// JSON ok=1
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["ok"].(float64) != 1 {
		t.Errorf("ok != 1: %v", resp)
	}
}

// TestVerifyJSON_BehavioralForgedCt locks the #2 fix: a behavioral submit whose
// signal scores high but whose proof-of-load token (ct) is missing/forged is
// rejected with no cookie, so a bot can't clear the CAPTCHA with a blind POST.
func TestVerifyJSON_BehavioralForgedCt(t *testing.T) {
	h := newTestHandler(t)
	body := `{"token":"x","ct":"99999.deadbeefdeadbeef","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected rejection for forged ct, got 200 body=%s", rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			t.Fatal("a _bv cookie was issued despite an invalid proof-of-load token")
		}
	}
}

// VerifyJSON: bot-like signal → 403 + no cookie.
func TestVerifyJSON_BehavioralFail(t *testing.T) {
	h := newTestHandler(t)
	body := `{"token":"x","sig":{"hasMouseEvents":false,"clickAt":50,"windowSize":[0,0]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			t.Errorf("did not expect _bv cookie on fail; got %q", c.Value)
		}
	}
}

// DebugBeacon: valid phase → INSERT succeeds, invalid phase → 400.
func TestDebugBeacon(t *testing.T) {
	h := newTestHandler(t)

	// In production ServeChallenge issues the beacon token and challenge.js
	// echoes it back.  The test bypasses that by issuing a valid token here
	// with the same secret + IP.
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase, "1.2.3.4")
	body := `{"phase":"load","flags":3,"reload_count":1,"ua":"x","bt":"` + bt + `"}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rr := httptest.NewRecorder()
	h.DebugBeacon(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("phase=load should be 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// A beacon without a token is rejected with 403 bad_token.
	noTok := `{"phase":"load"}`
	reqNoTok := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(noTok))
	reqNoTok.Header.Set("Content-Type", "application/json")
	reqNoTok.Header.Set("X-Real-IP", "1.2.3.4")
	rrNoTok := httptest.NewRecorder()
	h.DebugBeacon(rrNoTok, reqNoTok)
	if rrNoTok.Code != http.StatusForbidden {
		t.Errorf("tokenless beacon should be 403, got %d", rrNoTok.Code)
	}

	bad := `{"phase":"haxxor"}`
	req2 := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(bad))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	rr2 := httptest.NewRecorder()
	h.DebugBeacon(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("invalid phase should be 400, got %d", rr2.Code)
	}

	// Confirm 1 row was INSERTed.
	row := h.DB.QueryRowContext(context.Background(), "SELECT count(*) FROM unmask_event WHERE phase='load'")
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 inserted event, got %d", n)
	}
}

// CaptchaNew: a, b in [1,20], token is 64 hex chars.
func TestCaptchaNew(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/api/captcha/new", nil)
	rr := httptest.NewRecorder()
	h.CaptchaNew(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("captcha/new expected 200, got %d", rr.Code)
	}
	var resp struct {
		A, B  int
		Token string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.A < 1 || resp.A > 20 || resp.B < 1 || resp.B > 20 {
		t.Errorf("a/b out of [1,20]: %+v", resp)
	}
	// token format is "<issued>.<hmac>": a unix-second timestamp, a dot, then
	// the 64-char sha256 hex (now IP/time-bound, see captcha.MathChallenge).
	issued, sig, ok := strings.Cut(resp.Token, ".")
	if !ok || issued == "" || len(sig) != 64 {
		t.Errorf("token format want <issued>.<64-hex sha256>, got %q", resp.Token)
	}
}

// AdminMyIP: skips rDNS resolution; verifies is_loopback=true via loopback IP.
func TestAdminMyIP(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/myip?ip=127.0.0.1", nil)
	rr := httptest.NewRecorder()
	h.AdminMyIP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["family"] != "v4" {
		t.Errorf("family=v4 expected, got %v", resp["family"])
	}
	if resp["is_loopback"] != true {
		t.Errorf("is_loopback=true expected, got %v", resp["is_loopback"])
	}
}

// AdminMyIP invalid input.
func TestAdminMyIP_Invalid(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/myip?ip=zzz", nil)
	rr := httptest.NewRecorder()
	h.AdminMyIP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid ip should yield 400, got %d", rr.Code)
	}
}

// readBody helper for future tests.
func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestIPAllowed: exact + CIDR matching for admin_allowed_ips.
func TestIPAllowed(t *testing.T) {
	cases := []struct {
		name      string
		ip        string
		allowList []string
		want      bool
	}{
		{"empty list → allow all (compat)", "127.0.0.1", nil, true},
		{"empty list public → allow all", "1.2.3.4", nil, true},
		{"empty list invalid ip → allow all", "zzz", nil, true},
		{"exact match", "10.0.0.5", []string{"10.0.0.5"}, true},
		{"exact non-match", "10.0.0.6", []string{"10.0.0.5"}, false},
		{"CIDR /24 match", "10.0.0.99", []string{"10.0.0.0/24"}, true},
		{"CIDR /24 non-match", "10.0.1.99", []string{"10.0.0.0/24"}, false},
		{"v6 CIDR match", "2001:db8::1", []string{"2001:db8::/32"}, true},
		{"mixed list match later", "192.168.1.1", []string{"127.0.0.1", "192.168.1.0/24"}, true},
		{"non-empty list invalid IP rejected", "zzz", []string{"0.0.0.0/0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ipAllowed(c.ip, c.allowList)
			if got != c.want {
				t.Errorf("ipAllowed(%q, %v) = %v, want %v", c.ip, c.allowList, got, c.want)
			}
		})
	}
}

// TestResolveHostFilterEncodedCookie guards the multi-select host picker bug:
// the picker JS writes the cookie with encodeURIComponent, so a comma-joined
// host list arrives as "a%2Cb" — resolveHostFilter must percent-decode before
// splitting, otherwise two selected hosts collapse into one junk entry.
func TestResolveHostFilterEncodedCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(&http.Cookie{Name: "unmask_hosts", Value: "edge-tokyo-1%2Cedge-osaka-2"})
	got := resolveHostFilter(req)
	if len(got) != 2 || got[0] != "edge-tokyo-1" || got[1] != "edge-osaka-2" {
		t.Fatalf("resolveHostFilter = %v, want [edge-tokyo-1 edge-osaka-2]", got)
	}
	// a plain single value (= no encoding needed) still works.
	req2 := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req2.AddCookie(&http.Cookie{Name: "unmask_hosts", Value: "edge-tokyo-1"})
	if got := resolveHostFilter(req2); len(got) != 1 || got[0] != "edge-tokyo-1" {
		t.Fatalf("single host: resolveHostFilter = %v", got)
	}
}

// TestResolveSiteFilterEncodedCookie: an IPv6 site id keeps its colons through
// the encodeURIComponent / decode round-trip.
func TestResolveSiteFilterEncodedCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(&http.Cookie{Name: "unmask_site", Value: "2001%3Adb8%3A%3A1"})
	if got := resolveSiteFilter(req); got != "2001:db8::1" {
		t.Fatalf("resolveSiteFilter = %q, want 2001:db8::1", got)
	}
}

// TestResolveTZEncodedCookie: the picker JS writes the cookie via
// encodeURIComponent(), so "Asia/Tokyo" arrives as "Asia%2FTokyo".  Without a
// decode step the '%' fails the safety allowlist and the operator silently
// drops back to UTC -- the bug we are guarding against here.
func TestResolveTZEncodedCookie(t *testing.T) {
	cases := []struct{ cookie, wantTZ string }{
		{"Asia/Tokyo", "Asia/Tokyo"},
		{"Asia%2FTokyo", "Asia/Tokyo"},
		{"America%2FNew_York", "America/New_York"},
		{"Europe/London", "Europe/London"},
		{"auto", ""},
		{"browser", ""},
		{"", ""},
		{"%E6%97%A5%E6%9C%AC", ""}, // multi-byte junk falls through safety filter.
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
		if c.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "unmask_tz", Value: c.cookie})
		}
		if got := resolveTZ(req); got != c.wantTZ {
			t.Errorf("cookie=%q: resolveTZ = %q, want %q", c.cookie, got, c.wantTZ)
		}
	}
}

// TestIsHTMLNavigation drives the client-type detector used by
// ServeChallengeOrJSON.  Browser document navigation -> HTML challenge;
// fetch / XHR / explicit JSON Accept -> JSON 403.
func TestIsHTMLNavigation(t *testing.T) {
	mk := func(method string, headers map[string]string) *http.Request {
		req := httptest.NewRequest(method, "/api/foo", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req
	}
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			"browser navigation: Sec-Fetch-Dest=document",
			mk("GET", map[string]string{"Sec-Fetch-Dest": "document", "Accept": "text/html"}),
			true,
		},
		{
			"iframe load also HTML",
			mk("GET", map[string]string{"Sec-Fetch-Dest": "iframe"}),
			true,
		},
		{
			"fetch / XHR: Sec-Fetch-Dest=empty",
			mk("POST", map[string]string{"Sec-Fetch-Dest": "empty", "Accept": "*/*"}),
			false,
		},
		{
			"CORS POST without Sec-Fetch-Dest still classifies via Sec-Fetch-Mode",
			mk("POST", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "*/*"}),
			false,
		},
		{
			"explicit JSON Accept on POST is not HTML",
			mk("POST", map[string]string{"Accept": "application/json"}),
			false,
		},
		{
			"legacy GET with no fetch metadata + Accept text/html",
			mk("GET", map[string]string{"Accept": "text/html"}),
			true,
		},
		{
			"bare GET with no headers falls back to method (HTML)",
			mk("GET", map[string]string{}),
			true,
		},
		{
			"bare POST with no headers falls back to method (not HTML)",
			mk("POST", map[string]string{}),
			false,
		},
	}
	for _, c := range cases {
		got := isHTMLNavigation(c.req)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestServeChallengeOrJSON_NonHTMLClient verifies the JSON 403 path: API
// client gets application/json with a parseable body carrying challenge_url,
// retry_after, and reason.  This is the regression guard against the
// pre-v0.1 405 + "Method Not Allowed" leak.
func TestServeChallengeOrJSON_NonHTMLClient(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/unmask/_rl/api/foo", strings.NewReader(`{"any":"body"}`))
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")

	rr := httptest.NewRecorder()
	h.ServeChallengeOrJSON(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json*", ct)
	}
	if rr.Header().Get("Retry-After") != "600" {
		t.Errorf("Retry-After = %q, want 600", rr.Header().Get("Retry-After"))
	}
	if rr.Header().Get("X-Robots-Tag") == "" {
		t.Errorf("X-Robots-Tag missing")
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, rr.Body.String())
	}
	if body["error"] != "challenge_required" {
		t.Errorf("error = %v, want challenge_required", body["error"])
	}
	chURL, _ := body["challenge_url"].(string)
	if !strings.HasPrefix(chURL, "/unmask/challenge/") {
		t.Errorf("challenge_url = %q, want prefix /unmask/challenge/", chURL)
	}
	// _rl/api/foo -> orig_path /api/foo -> challenge_url should embed it.
	if !strings.Contains(chURL, "_orig=") {
		t.Errorf("challenge_url missing _orig= query: %q", chURL)
	}
	if body["reason"] != "rate_limit" {
		t.Errorf("reason = %v, want rate_limit (path was /_rl/...)", body["reason"])
	}
	if body["retry_after"].(float64) != 600 {
		t.Errorf("retry_after = %v, want 600", body["retry_after"])
	}
}

// TestServeChallengeOrJSON_HTMLClient verifies the HTML challenge path stays
// the default for browser navigation.  We don't exercise the full HTML body
// (= templates / placeholders need more setup); we just check the response
// is HTML-shaped rather than JSON.
func TestServeChallengeOrJSON_HTMLClient(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Real-IP", "1.2.3.4")

	rr := httptest.NewRecorder()
	h.ServeChallengeOrJSON(rr, req)

	// HTML branch may 500 if the embedded asset isn't loaded in this test
	// (= newTestHandler doesn't wire up assets).  Either way it must NOT be
	// a JSON 403 with the API shape.
	if ct := rr.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		t.Errorf("HTML client got JSON Content-Type %q (= took the API branch by mistake)", ct)
	}
}
