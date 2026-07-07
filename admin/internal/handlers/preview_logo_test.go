package handlers

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// the preview store evicts by age and by count, and treats an expired entry as
// absent (reaping it on read).
func TestPreviewLogoStore(t *testing.T) {
	s := &previewLogoStore{m: make(map[string]previewLogoEntry)}
	t0 := time.Unix(1_700_000_000, 0)

	s.put("aa", []byte("png-bytes"), "image/png", t0)
	if e, ok := s.get("aa", t0.Add(5*time.Minute)); !ok || string(e.data) != "png-bytes" || e.ct != "image/png" {
		t.Fatalf("get within TTL: ok=%v entry=%+v", ok, e)
	}
	// past the TTL -> gone (and reaped).
	if _, ok := s.get("aa", t0.Add(previewLogoTTL+time.Second)); ok {
		t.Fatalf("expected expired token to be absent")
	}
	s.mu.Lock()
	_, still := s.m["aa"]
	s.mu.Unlock()
	if still {
		t.Fatalf("expired entry was not reaped on read")
	}

	// count eviction: insert one past capacity, oldest should be dropped.
	s2 := &previewLogoStore{m: make(map[string]previewLogoEntry)}
	for i := 0; i < previewLogoMaxEntry+1; i++ {
		// distinct, monotonically increasing timestamps so "oldest" is well-defined
		s2.put(string(rune('a'+i)), []byte{byte(i)}, "image/png", t0.Add(time.Duration(i)*time.Second))
	}
	s2.mu.Lock()
	n := len(s2.m)
	_, oldestPresent := s2.m["a"] // the very first insert
	s2.mu.Unlock()
	if n > previewLogoMaxEntry {
		t.Fatalf("store exceeded cap: %d > %d", n, previewLogoMaxEntry)
	}
	if oldestPresent {
		t.Fatalf("oldest entry should have been evicted at capacity")
	}
}

func TestIsPreviewLogoToken(t *testing.T) {
	valid := strings.Repeat("a", previewLogoTokenLen*2) // 32 hex chars
	cases := []struct {
		in   string
		want bool
	}{
		{valid, true},
		{"0123456789abcdef0123456789abcdef", true},
		{"", false},
		{strings.Repeat("a", 31), false}, // too short
		{strings.Repeat("a", 33), false}, // too long
		{strings.Repeat("g", 32), false}, // non-hex
		{strings.Repeat("A", 32), false}, // uppercase not minted
		{"../../etc/passwd0000000000000000", false},
	}
	for _, c := range cases {
		if got := isPreviewLogoToken(c.in); got != c.want {
			t.Errorf("isPreviewLogoToken(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// the live-preview override URL wins over the saved LogoPath in the challenge
// brand JSON; with no override the saved logo route is used.
func TestBrandingInjectJSONLogoOverride(t *testing.T) {
	br := settings.BrandingValues{LogoPath: "/nonexistent/logo.png"}
	override := "/unmask/admin/test/preview-logo?t=" + strings.Repeat("a", 32)

	withOverride := brandingInjectJSON(br, "/unmask", override, false)
	if !strings.Contains(withOverride, "preview-logo") {
		t.Fatalf("override URL missing from brand JSON: %s", withOverride)
	}
	if strings.Contains(withOverride, "/branding/logo") {
		t.Fatalf("saved logo route leaked despite override: %s", withOverride)
	}

	saved := brandingInjectJSON(br, "/unmask", "", false)
	if !strings.Contains(saved, "/branding/logo") {
		t.Fatalf("saved logo route missing without override: %s", saved)
	}
	if strings.Contains(saved, "preview-logo") {
		t.Fatalf("preview route present without override: %s", saved)
	}

	// suppress: the removed-state preview shows no logo even with one saved,
	// and even if a token override is also (nonsensically) supplied.
	suppressed := brandingInjectJSON(br, "/unmask", override, true)
	if strings.Contains(suppressed, "logo_url") {
		t.Fatalf("suppressLogo still emitted a logo_url: %s", suppressed)
	}
}

// the deny page renders the live-preview logo override when set, and falls back
// to the saved branding logo route (or no <img>) otherwise.
func TestDenyLogoOverride(t *testing.T) {
	override := "/unmask/admin/test/preview-logo?t=" + strings.Repeat("b", 32)

	got := string(renderRateDenyC(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "ref", denyColors{LogoURL: override}))
	if !strings.Contains(got, `src="`+override+`"`) {
		t.Fatalf("deny page missing preview logo override:\n%s", got)
	}

	saved := string(renderRateDenyC(settings.BrandingValues{LogoPath: "/x/logo.png"}, "friendly", "auto", "en", "/unmask", "ref", denyColors{}))
	if !strings.Contains(saved, `src="/unmask/branding/logo"`) {
		t.Fatalf("deny page missing saved logo route:\n%s", saved)
	}

	none := string(renderRateDenyC(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "ref", denyColors{}))
	if strings.Contains(none, `class="logo"`) {
		t.Fatalf("deny page emitted a logo img with no logo configured:\n%s", none)
	}

	// suppress: the removed-state preview shows no <img> even with a saved logo.
	suppressed := string(renderRateDenyC(settings.BrandingValues{LogoPath: "/x/logo.png"}, "friendly", "auto", "en", "/unmask", "ref", denyColors{SuppressLogo: true}))
	if strings.Contains(suppressed, `class="logo"`) {
		t.Fatalf("deny page emitted a logo img despite SuppressLogo:\n%s", suppressed)
	}
}

func multipartLogo(t *testing.T, field, filename string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close mw: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// end-to-end: upload a PNG -> token -> serve streams the same bytes; an unknown
// or malformed token 404s.
func TestPreviewLogoUploadServeRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	png := []byte("\x89PNG\r\n\x1a\nfake-image-bytes")

	body, ct := multipartLogo(t, "branding_logo_file", "logo.png", png)
	req := httptest.NewRequest(http.MethodPost, "/admin/test/preview-logo", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.PreviewLogoUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out struct{ Token, URL string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode upload json: %v (%s)", err, rec.Body.String())
	}
	if !isPreviewLogoToken(out.Token) {
		t.Fatalf("upload returned a malformed token: %q", out.Token)
	}
	if !strings.Contains(out.URL, out.Token) {
		t.Fatalf("upload URL %q missing token %q", out.URL, out.Token)
	}

	// serve the token back
	sreq := httptest.NewRequest(http.MethodGet, "/admin/test/preview-logo?t="+out.Token, nil)
	srec := httptest.NewRecorder()
	h.PreviewLogoServe(srec, sreq)
	if srec.Code != http.StatusOK {
		t.Fatalf("serve status = %d, want 200", srec.Code)
	}
	if got := srec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("serve content-type = %q, want image/png", got)
	}
	if !bytes.Equal(srec.Body.Bytes(), png) {
		t.Fatalf("serve body mismatch: got %q want %q", srec.Body.Bytes(), png)
	}

	// unknown but well-formed token -> 404
	ureq := httptest.NewRequest(http.MethodGet, "/admin/test/preview-logo?t="+strings.Repeat("c", 32), nil)
	urec := httptest.NewRecorder()
	h.PreviewLogoServe(urec, ureq)
	if urec.Code != http.StatusNotFound {
		t.Fatalf("unknown token status = %d, want 404", urec.Code)
	}

	// malformed token -> 404 (never reaches the store)
	mreq := httptest.NewRequest(http.MethodGet, "/admin/test/preview-logo?t=not-a-token", nil)
	mrec := httptest.NewRecorder()
	h.PreviewLogoServe(mrec, mreq)
	if mrec.Code != http.StatusNotFound {
		t.Fatalf("malformed token status = %d, want 404", mrec.Code)
	}
}

// an uploaded SVG is script-stripped before it is served, and carries the
// locked-down CSP so it cannot run script as a top-level document.
func TestPreviewLogoSVGSanitized(t *testing.T) {
	h := newTestHandler(t)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect/></svg>`)

	body, ct := multipartLogo(t, "branding_logo_file", "logo.svg", svg)
	req := httptest.NewRequest(http.MethodPost, "/admin/test/preview-logo", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.PreviewLogoUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("svg upload status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out struct{ Token, URL string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	sreq := httptest.NewRequest(http.MethodGet, "/admin/test/preview-logo?t="+out.Token, nil)
	srec := httptest.NewRecorder()
	h.PreviewLogoServe(srec, sreq)
	if srec.Code != http.StatusOK {
		t.Fatalf("svg serve status = %d", srec.Code)
	}
	if got := srec.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("svg content-type = %q", got)
	}
	if csp := srec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Fatalf("svg serve missing sandbox CSP: %q", csp)
	}
	if strings.Contains(srec.Body.String(), "<script") || strings.Contains(srec.Body.String(), "alert(1)") {
		t.Fatalf("served SVG still contains script: %s", srec.Body.String())
	}
}

// a rejected upload (bad extension / no file) does not 500.
func TestPreviewLogoUploadRejects(t *testing.T) {
	h := newTestHandler(t)

	body, ct := multipartLogo(t, "branding_logo_file", "logo.txt", []byte("nope"))
	req := httptest.NewRequest(http.MethodPost, "/admin/test/preview-logo", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.PreviewLogoUpload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad extension status = %d, want 400", rec.Code)
	}

	// wrong field name -> no file -> 400
	body2, ct2 := multipartLogo(t, "wrong_field", "logo.png", []byte("x"))
	req2 := httptest.NewRequest(http.MethodPost, "/admin/test/preview-logo", body2)
	req2.Header.Set("Content-Type", ct2)
	rec2 := httptest.NewRecorder()
	h.PreviewLogoUpload(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing file status = %d, want 400", rec2.Code)
	}
}
