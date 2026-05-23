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

	"github.com/shoeisha/unmask/admin/internal/db"
	"github.com/shoeisha/unmask/admin/internal/settings"
)

// newTestHandler builds a Handler backed by a temporary sqlite file.
// schema は file 1 つで完結させたいので CREATE TABLE を直接流す.
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
            ip_address BLOB NOT NULL,
            user_agent VARCHAR(255),
            ja4 VARCHAR(40),
            ja4_verdict VARCHAR(40),
            phase VARCHAR(16) NOT NULL,
            flags INTEGER NOT NULL DEFAULT 0,
            reload_count INTEGER NOT NULL DEFAULT 0,
            cookie_bv VARCHAR(80),
            cookie_br VARCHAR(8),
            payload_json TEXT,
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
		Challenge: settings.Challenge{
			CookieDays:            3,
			CaptchaScoreThreshold: 0.5,
			DebugRateLimitPer5Min: 100,
		},
	}
	return &Handler{DB: conn, Settings: s}
}

// VerifyJSON: high score → 200 ok=1 + Set-Cookie _bv.
func TestVerifyJSON_BehavioralPass(t *testing.T) {
	h := newTestHandler(t)
	body := `{"token":"x","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`
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

// BVCheck: cookie 無し → 403, valid 発行直後 → 204, 別 IP → 403.
func TestBVCheck_Roundtrip(t *testing.T) {
	h := newTestHandler(t)
	// まず /api/verify で正規 cookie を発行
	body := `{"token":"x","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("X-Client-JA4", "t13d1517h2_aaa_bbb")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)
	var bv string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			bv = c.Value
		}
	}
	if bv == "" {
		t.Fatal("could not obtain _bv cookie")
	}

	// bv-check: 同 IP+JA4 → 204
	req2 := httptest.NewRequest(http.MethodGet, "/unmask/api/bv-check", nil)
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	req2.Header.Set("X-Client-JA4", "t13d1517h2_aaa_bbb")
	req2.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	rr2 := httptest.NewRecorder()
	h.BVCheck(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Errorf("same IP+JA4 should yield 204, got %d", rr2.Code)
	}

	// bv-check: 別 IP → 403 (= replay 防止)
	req3 := httptest.NewRequest(http.MethodGet, "/unmask/api/bv-check", nil)
	req3.Header.Set("X-Real-IP", "9.9.9.9")
	req3.Header.Set("X-Client-JA4", "t13d1517h2_aaa_bbb")
	req3.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	rr3 := httptest.NewRecorder()
	h.BVCheck(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Errorf("different IP should yield 403, got %d", rr3.Code)
	}

	// bv-check: cookie 無し → 403
	req4 := httptest.NewRequest(http.MethodGet, "/unmask/api/bv-check", nil)
	req4.Header.Set("X-Real-IP", "1.2.3.4")
	rr4 := httptest.NewRecorder()
	h.BVCheck(rr4, req4)
	if rr4.Code != http.StatusForbidden {
		t.Errorf("no cookie should yield 403, got %d", rr4.Code)
	}
}

// DebugBeacon: 有効 phase → INSERT 成功, 不正 phase → 400.
func TestDebugBeacon(t *testing.T) {
	h := newTestHandler(t)

	body := `{"phase":"load","flags":3,"reload_count":1,"ua":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rr := httptest.NewRecorder()
	h.DebugBeacon(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("phase=load should be 200, got %d body=%s", rr.Code, rr.Body.String())
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

	// 1 件 INSERT されたことを確認
	row := h.DB.QueryRowContext(context.Background(), "SELECT count(*) FROM unmask_event WHERE phase='load'")
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 inserted event, got %d", n)
	}
}

// CaptchaNew: a, b in [1,20], token は 64 hex.
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
	if len(resp.Token) != 64 {
		t.Errorf("token length expected 64 (sha256 hex), got %d", len(resp.Token))
	}
}

// AdminMyIP: rDNS 解決の代わりに loopback で is_loopback=true を確認.
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
