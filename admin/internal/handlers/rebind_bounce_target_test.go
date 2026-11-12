package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// The bounce after a silent rebind sends the visitor to the page they asked
// for, whole.  It sent them to the first 200 bytes of its URL -- the length
// the event row keeps -- so a page with a longer query came back as another
// page, and a URL cut inside a percent escape as nginx's 400.
func TestRebindBouncesToTheWholeURL(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	// 190 bytes of path and query, then a percent-escaped character across
	// byte 200, then more.
	long := "/search?q=" + strings.Repeat("a", 180) + "%E3%81%82%E3%81%84&page=2&utm_source=" + strings.Repeat("s", 120)
	if len(long) < 300 {
		t.Fatalf("the test's URL is %d bytes; it has to be well past 200", len(long))
	}

	bounce := func(t *testing.T, orig string) (target string, body string) {
		t.Helper()
		h := newRebindTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/?_orig="+url.QueryEscape(orig), nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		req.Header.Set("X-JA4-Verdict", "ok")
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: cookies.IssueJValue("test-secret",
			cookies.FingerprintHash(ja4), cookies.FingerprintHash(ua),
			"linrebind0000000000000000", 0, "example.com", "captcha")})
		rr := httptest.NewRecorder()
		if !h.tryRebind(rr, req, "default", "bttest00.bounce") {
			t.Fatal("the rebind was refused; this test needs one that passes")
		}
		body = rr.Body.String()
		m := regexp.MustCompile(`var o=("(?:[^"\\]|\\.)*")`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("the bounce page names no target: %s", body)
		}
		target, err := strconv.Unquote(m[1])
		if err != nil {
			t.Fatalf("the bounce page's target %s: %v", m[1], err)
		}
		return target, body
	}

	target, body := bounce(t, long)
	if target != long {
		t.Errorf("the bounce sends the visitor to %d bytes of a %d-byte URL:\n  got  %s\n  want %s", len(target), len(long), target, long)
	}
	if !strings.Contains(body, `content="0; url=`) {
		t.Error("the bounce page's meta refresh names no URL")
	}

	// Still never off this site, and nothing absurd echoed into the page.
	for _, orig := range []string{"https://evil.example/x", "//evil.example/x", "/\t/evil.example", "/" + strings.Repeat("a", rebindOrigMax)} {
		if target, _ := bounce(t, orig); target != "" {
			t.Errorf("_orig=%.40q…: the bounce names %.60q as its target, want none", orig, target)
		}
	}
}
