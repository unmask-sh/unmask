package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// scriptFileTagRE: the tag of the script's file, as ServeChallenge writes it.
var scriptFileTagRE = regexp.MustCompile(`<script nonce="([^"]+)" id="unmask-js" src="/unmask/static/(challenge\.[0-9a-f]{16}\.js)" defer></script>`)

// serveChallengePage asks for the challenge page the way the module's nginx
// does (viaModule: server.inc's X-Unmask-Local-Port) or directly, from an
// address of its own, and waits for the serve event so that no test leaves
// one being written.
func serveChallengePage(t *testing.T, h *Handler, ip string, viaModule bool, cookie string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("X-Real-IP", ip)
	if viaModule {
		req.Header.Set("X-Unmask-Local-Port", "443")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)
	var payload map[string]any
	waitFor(t, "the serve event of "+ip, 3*time.Second, func() bool {
		var raw string
		err := h.DB.QueryRowContext(context.Background(),
			`SELECT COALESCE(payload_json, '') FROM unmask_event
			  WHERE phase = 'serve' AND ip_address = ? ORDER BY id DESC LIMIT 1`, events.PackIP(ip)).Scan(&raw)
		if err != nil || raw == "" {
			return false
		}
		payload = nil
		return json.Unmarshal([]byte(raw), &payload) == nil
	})
	return rr, payload
}

// TestServeChallenge_ScriptAsAFile: through the module, the page names the
// script's file and does not carry the script; the file is this daemon's
// script, under the hash of what it serves, for a browser to keep.
func TestServeChallenge_ScriptAsAFile(t *testing.T) {
	h := newTestHandler(t)
	rr, payload := serveChallengePage(t, h, "203.0.113.31", true, "")
	body := rr.Body.String()

	m := scriptFileTagRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the page does not name the script's file:\n%s", tail(body, 600))
	}
	nonce, name := m[1], m[2]
	if strings.Contains(body, "_bv_set_ok") {
		t.Error("the page names the file and carries the script as well")
	}
	if !strings.Contains(body, "/*__JS_INLINE__*/0") || strings.Contains(body, "/*__JS_INLINE__*/1") {
		t.Error("the page does not tell its own script that the challenge script is a file (js_inline 0)")
	}
	if strings.Contains(body, "__BUILD_V__") || strings.Contains(body, `src="/unmask/static/challenge.js`) {
		t.Error("the page still names the plain file")
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "'nonce-"+nonce+"'") || !strings.Contains(csp, "'self'") {
		t.Errorf("the tag's nonce %q is not the policy's, or the policy lost 'self': %s", nonce, csp)
	}
	// What a client that runs nothing is sent: the page, a fifth of what it
	// was with the script inside (the script alone is over 80 kB).
	if len(body) > 45000 {
		t.Errorf("the page is %d bytes without the script", len(body))
	}
	if _, asked := payload["js_in_page"]; asked {
		t.Errorf("the serve is recorded as asked for with the script inside: %v", payload)
	}

	get := func(asset, acceptEncoding string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/unmask/static/"+asset, nil)
		req.SetPathValue("asset", asset)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		w := httptest.NewRecorder()
		h.ServeChallengeJSNamed(w, req)
		return w
	}
	file := get(name, "")
	if file.Code != http.StatusOK {
		t.Fatalf("%s: status %d", name, file.Code)
	}
	js := file.Body.Bytes()
	if sum := sha256.Sum256(js); "challenge."+hex.EncodeToString(sum[:8])+".js" != name {
		t.Errorf("%s is not named after its content", name)
	}
	if !bytes.Contains(js, []byte("_bv_set_ok")) || !bytes.Contains(js, []byte("window.__unmaskStarted = true")) {
		t.Error("the file is not the challenge script")
	}
	if cc := file.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control %q: a browser would ask for the file again", cc)
	}
	if ct := file.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
		t.Errorf("Content-Type %q", ct)
	}
	if file.Header().Get("X-Content-Type-Options") != "nosniff" || file.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("headers: %v", file.Header())
	}
	if file.Header().Get("Content-Encoding") != "" {
		t.Error("compressed for a client that did not ask")
	}

	// The built-in script goes out without its comments.
	src, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(js)*10 > len(src)*7 {
		t.Errorf("the file is %d bytes of the source's %d: the comments are still in it", len(js), len(src))
	}

	// Compressed by the daemon for a client that takes gzip, whatever nginx
	// is set to compress.
	for _, ae := range []string{"gzip", "br, gzip;q=0.8", "deflate, GZIP"} {
		z := get(name, ae)
		if z.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding %q: not compressed", ae)
			continue
		}
		sent := z.Body.Len()
		zr, err := gzip.NewReader(z.Body)
		if err != nil {
			t.Fatalf("Accept-Encoding %q: %v", ae, err)
		}
		plain, _ := io.ReadAll(zr)
		if !bytes.Equal(plain, js) {
			t.Errorf("Accept-Encoding %q: the compressed file is another file", ae)
		}
		if sent*2 > len(js) {
			t.Errorf("Accept-Encoding %q: %d bytes sent for a file of %d", ae, sent, len(js))
		}
	}
	for _, ae := range []string{"identity", "gzip;q=0", "br"} {
		if z := get(name, ae); z.Header().Get("Content-Encoding") != "" || !bytes.Equal(z.Body.Bytes(), js) {
			t.Errorf("Accept-Encoding %q: compressed", ae)
		}
	}

	// Another build's name is not here, and the miss is not kept: the page
	// that asked falls back to the script inside the page.
	for _, other := range []string{"challenge.0123456789abcdef.js", "challenge.js.map", "icon.svg", name + "x"} {
		miss := get(other, "gzip")
		if miss.Code != http.StatusNotFound || miss.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: status %d, Cache-Control %q; want 404 and no-store", other, miss.Code, miss.Header().Get("Cache-Control"))
		}
		if bytes.Contains(miss.Body.Bytes(), []byte("_bv_set_ok")) {
			t.Errorf("%s: answered with the script", other)
		}
	}

	// The plain name still answers, for a copy of the page that names it.
	req := httptest.NewRequest(http.MethodGet, "/unmask/static/challenge.js", nil)
	w := httptest.NewRecorder()
	h.ServeChallengeJS(w, req)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), js) || w.Header().Get("Cache-Control") != "public, max-age=600" {
		t.Errorf("/static/challenge.js: status %d, %d bytes, Cache-Control %q", w.Code, w.Body.Len(), w.Header().Get("Cache-Control"))
	}
}

// TestServeChallenge_ScriptInPage: the page carries the script wherever a
// browser that cannot load the file would otherwise be left on a challenge
// that never runs -- the loop the script was once always in the page for.
func TestServeChallenge_ScriptInPage(t *testing.T) {
	inPage := func(t *testing.T, rr *httptest.ResponseRecorder) {
		t.Helper()
		body := rr.Body.String()
		if scriptFileTagRE.MatchString(body) || strings.Contains(body, `src="/unmask/static/challenge`) {
			t.Error("the page names a file for the script: a browser that cannot load it never runs the challenge")
		}
		if !strings.Contains(body, "_bv_set_ok") {
			t.Error("the script is not in the page")
		}
		if !strings.Contains(body, "/*__JS_INLINE__*/1") {
			t.Error("the page does not tell its own script that the challenge script is inside (js_inline 1): it would ask for the page again")
		}
		if strings.Contains(body, "\n  // The first statement, before anything that could throw") {
			t.Error("the script in the page still has its comments")
		}
	}

	t.Run("the browser asked for it", func(t *testing.T) {
		h := newTestHandler(t)
		rr, payload := serveChallengePage(t, h, "203.0.113.32", true, "_bvi=1")
		inPage(t, rr)
		if payload["js_in_page"] != float64(1) {
			t.Errorf("the serve does not say the browser asked (js_in_page): %v", payload)
		}
	})
	t.Run("not through the module", func(t *testing.T) {
		// Forward-auth, Apache, a request made of the daemon: no header from
		// server.inc.  Nothing asked, so nothing is recorded as asked.
		h := newTestHandler(t)
		rr, payload := serveChallengePage(t, h, "203.0.113.33", false, "")
		inPage(t, rr)
		if _, asked := payload["js_in_page"]; asked {
			t.Errorf("recorded as asked for: %v", payload)
		}
	})
	t.Run("the operator's setting", func(t *testing.T) {
		h := newTestHandler(t)
		cur := h.snapshotSettings()
		cur.Challenge.Default.ChallengeJSInline = settings.BoolPtr(true)
		h.SetSettings(cur)
		rr, _ := serveChallengePage(t, h, "203.0.113.34", true, "")
		inPage(t, rr)
	})
	t.Run("a copy of the page from before the file", func(t *testing.T) {
		// It has no script that would ask for the page again.
		h := newTestHandler(t)
		page, err := assets.Static.ReadFile("static/challenge.html")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(page, []byte(" js_inline: "+jsInlinePlaceholder+",")) {
			t.Fatal("challenge.html does not carry the js_inline placeholder")
		}
		old := bytes.Replace(page, []byte(" js_inline: "+jsInlinePlaceholder+","), nil, 1)
		mine := filepath.Join(t.TempDir(), "challenge.html")
		if err := os.WriteFile(mine, old, 0o644); err != nil {
			t.Fatal(err)
		}
		cur := h.snapshotSettings()
		cur.Challenge.Default.ChallengeHTMLPath = mine
		h.SetSettings(cur)
		rr, _ := serveChallengePage(t, h, "203.0.113.35", true, "")
		body := rr.Body.String()
		if scriptFileTagRE.MatchString(body) || !strings.Contains(body, "_bv_set_ok") {
			t.Error("an older copy of the page was served without the script inside")
		}
	})
}

// TestServeChallenge_OperatorsScript: an operator's own challenge.js is
// served as they wrote it, under the hash of that, and followed when the file
// changes.
func TestServeChallenge_OperatorsScript(t *testing.T) {
	h := newTestHandler(t)
	mine := filepath.Join(t.TempDir(), "mine.js")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(mine, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first := "// the operator's own\nwindow.__unmaskStarted = true; var _bv_set_ok = 1; // theirs\n"
	write(first)
	cur := h.snapshotSettings()
	cur.Challenge.Default.ChallengeJSPath = mine
	h.SetSettings(cur)

	named := func(ip string) (string, string) {
		t.Helper()
		rr, _ := serveChallengePage(t, h, ip, true, "")
		m := scriptFileTagRE.FindStringSubmatch(rr.Body.String())
		if m == nil {
			t.Fatalf("the page does not name the operator's script as a file")
		}
		req := httptest.NewRequest(http.MethodGet, "/unmask/static/"+m[2], nil)
		req.SetPathValue("asset", m[2])
		w := httptest.NewRecorder()
		h.ServeChallengeJSNamed(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", m[2], w.Code)
		}
		return m[2], w.Body.String()
	}
	name1, got := named("203.0.113.36")
	if got != first {
		t.Errorf("the operator's script was not served as written: %q", got)
	}
	second := first + "var changed = 1;\n"
	write(second)
	name2, got := named("203.0.113.37")
	if got != second || name2 == name1 {
		t.Errorf("the changed file: name %s (was %s), body %q", name2, name1, got)
	}
	// The name of what it was is gone with it.
	req := httptest.NewRequest(http.MethodGet, "/unmask/static/"+name1, nil)
	req.SetPathValue("asset", name1)
	w := httptest.NewRecorder()
	h.ServeChallengeJSNamed(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("the old name still answers: %d", w.Code)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
