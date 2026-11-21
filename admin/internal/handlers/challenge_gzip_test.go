package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// askPage asks for a challenge page from an address of its own, with the
// headers given ("Host" names the site), and waits for the serve event so
// that no test leaves one being written.
func askPage(t *testing.T, h *Handler, ip, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Real-IP", ip)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)
	waitFor(t, "the serve event of "+ip, 3*time.Second, func() bool {
		var n int
		err := h.DB.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM unmask_event WHERE phase = 'serve' AND ip_address = ?`, events.PackIP(ip)).Scan(&n)
		return err == nil && n > 0
	})
	return rr
}

// throughModuleGzip: what server.inc's request for a browser looks like.
func throughModuleGzip() map[string]string {
	return map[string]string{"X-Unmask-Local-Port": "443", "Accept-Encoding": "gzip, deflate, br, zstd"}
}

// gunzipped reads a whole gzip body, to its end and its checksum.
func gunzipped(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v (first bytes %q)", err, b[:min(len(b), 16)])
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("the gzip body does not read to its end: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("the gzip body's checksum: %v", err)
	}
	return string(out)
}

// compressedPage: the answer is gzip, says so, and holds a whole page.
func compressedPage(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	if enc := rr.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding %q, want gzip (%d bytes, starting %q)", enc, rr.Body.Len(), rr.Body.Bytes()[:min(rr.Body.Len(), 16)])
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length %q for a body of %d bytes", cl, rr.Body.Len())
	}
	if !strings.Contains(strings.Join(rr.Header().Values("Vary"), ","), "Accept-Encoding") {
		t.Errorf("a compressed page without Vary: Accept-Encoding (%q)", rr.Header().Values("Vary"))
	}
	page := gunzipped(t, rr.Body.Bytes())
	if !strings.HasPrefix(strings.TrimSpace(page), "<!") || !strings.Contains(page, "</html>") {
		t.Fatalf("what the client decodes is not a whole page: starts %q, ends %q", page[:min(len(page), 40)], tail(page, 40))
	}
	return page
}

// plainPage: the answer is the page as it is.
func plainPage(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	if enc := rr.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("Content-Encoding %q on a page that should leave as it is", enc)
	}
	page := rr.Body.String()
	if !strings.HasPrefix(strings.TrimSpace(page), "<!") || !strings.Contains(page, "</html>") {
		t.Fatalf("not a whole page: starts %q", page[:min(len(page), 40)])
	}
	return page
}

// TestChallengePageGzip_ThroughTheModule: a browser's request that came
// through the module is answered with the page compressed by the daemon --
// the same page, a third of the size, with the status and the headers the
// page has always had.
func TestChallengePageGzip_ThroughTheModule(t *testing.T) {
	h := newTestHandler(t)
	plain := plainPage(t, askPage(t, h, "203.0.113.61", "/unmask/challenge/", map[string]string{"X-Unmask-Local-Port": "443"}))

	rr := askPage(t, h, "203.0.113.62", "/unmask/challenge/", throughModuleGzip())
	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rr.Code)
	}
	page := compressedPage(t, rr)
	if !scriptFileTagRE.MatchString(page) {
		t.Errorf("the decoded page does not name the script's file:\n%s", tail(page, 400))
	}
	// The two pages differ in what is drawn for each serve (the nonce, the
	// seed, the reference), never in length by more than a few bytes.
	if d := len(page) - len(plain); d < -64 || d > 64 {
		t.Errorf("the decoded page is %d bytes and the page as it is %d: not the same page", len(page), len(plain))
	}
	if rr.Body.Len()*100 > len(page)*45 {
		t.Errorf("%d bytes for a page of %d: that is not what compressing it is for", rr.Body.Len(), len(page))
	}
	for k, want := range map[string]string{
		"Content-Type":           "text/html; charset=utf-8",
		"Cache-Control":          "no-store, no-cache, must-revalidate",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rr.Header().Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("the compressed page lost its Content-Security-Policy")
	}
}

// TestChallengePageGzip_OnlyForAClientThatReadsIt: what the client says it
// reads decides, and saying nothing is reading nothing.
func TestChallengePageGzip_OnlyForAClientThatReadsIt(t *testing.T) {
	h := newTestHandler(t)
	for i, c := range []struct {
		accept string
		gz     bool
	}{
		{"", false},
		{"identity", false},
		{"br", false},
		{"deflate, br", false},
		{"gzip;q=0", false},
		{"gzip;q=0, br", false},
		{"gzip", true},
		{"GZIP", true},
		{"br;q=1.0, gzip;q=0.8", true},
		{"deflate,gzip", true},
	} {
		hdr := map[string]string{"X-Unmask-Local-Port": "443"}
		if c.accept != "" {
			hdr["Accept-Encoding"] = c.accept
		}
		rr := askPage(t, h, fmt.Sprintf("203.0.113.%d", 70+i), "/unmask/challenge/", hdr)
		if c.gz {
			compressedPage(t, rr)
			continue
		}
		plainPage(t, rr)
		// The answer could have been the other one: a cache has to be told.
		if !strings.Contains(strings.Join(rr.Header().Values("Vary"), ","), "Accept-Encoding") {
			t.Errorf("Accept-Encoding %q: the page as it is, without Vary: Accept-Encoding", c.accept)
		}
	}
}

// TestChallengePageGzip_NotOutsideTheModule: forward-auth, Apache and a
// request made of the daemon directly carry no header from server.inc, and
// are answered as they always were -- to the byte of the headers.
func TestChallengePageGzip_NotOutsideTheModule(t *testing.T) {
	h := newTestHandler(t)
	rr := askPage(t, h, "203.0.113.91", "/unmask/challenge/", map[string]string{"Accept-Encoding": "gzip, deflate, br"})
	plainPage(t, rr)
	if v := rr.Header().Values("Vary"); len(v) != 0 {
		t.Errorf("Vary %q on a request that did not come through the module", v)
	}
	if cl := rr.Header().Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length %q set on a request that did not come through the module", cl)
	}
}

// TestChallengePageGzip_TheOperatorsSetting: challenge_page_gzip: false hands
// nginx the page as it is, for the whole install or for one site.
func TestChallengePageGzip_TheOperatorsSetting(t *testing.T) {
	t.Run("off for the install", func(t *testing.T) {
		h := newTestHandler(t)
		cur := h.snapshotSettings()
		cur.Challenge.Default.ChallengePageGzip = settings.BoolPtr(false)
		h.SetSettings(cur)
		rr := askPage(t, h, "203.0.113.101", "/unmask/challenge/", throughModuleGzip())
		plainPage(t, rr)
		// Nothing of the daemon's answer depends on what the client reads now.
		if v := rr.Header().Values("Vary"); len(v) != 0 {
			t.Errorf("Vary %q with the daemon's compression off", v)
		}
	})
	t.Run("off for one site", func(t *testing.T) {
		h := newTestHandler(t)
		cur := h.snapshotSettings()
		if cur.Challenge.Sites == nil {
			cur.Challenge.Sites = map[string]settings.ChallengeValues{}
		}
		cur.Challenge.Sites["plain.example"] = settings.ChallengeValues{ChallengePageGzip: settings.BoolPtr(false)}
		h.SetSettings(cur)
		hdr := throughModuleGzip()
		hdr["Host"] = "plain.example"
		plainPage(t, askPage(t, h, "203.0.113.102", "/unmask/challenge/", hdr))
		hdr["Host"] = "other.example"
		compressedPage(t, askPage(t, h, "203.0.113.103", "/unmask/challenge/", hdr))
	})
	t.Run("on for one site of an install that turned it off", func(t *testing.T) {
		h := newTestHandler(t)
		cur := h.snapshotSettings()
		cur.Challenge.Default.ChallengePageGzip = settings.BoolPtr(false)
		if cur.Challenge.Sites == nil {
			cur.Challenge.Sites = map[string]settings.ChallengeValues{}
		}
		cur.Challenge.Sites["packed.example"] = settings.ChallengeValues{ChallengePageGzip: settings.BoolPtr(true)}
		h.SetSettings(cur)
		hdr := throughModuleGzip()
		hdr["Host"] = "packed.example"
		compressedPage(t, askPage(t, h, "203.0.113.104", "/unmask/challenge/", hdr))
	})
}

// TestChallengePageGzip_TheRateLimitsPage: the page a rate limit answers with
// is a 429, the one status nginx's own gzip never compresses.
func TestChallengePageGzip_TheRateLimitsPage(t *testing.T) {
	h := newTestHandler(t)
	rr := askPage(t, h, "203.0.113.111", "/unmask/_rl/docs/", throughModuleGzip())
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rr.Code)
	}
	compressedPage(t, rr)
}

// TestChallengePageGzip_ThePageWithTheScriptInside: the larger page, sent to
// a browser the script's file did not reach, is compressed as well.
func TestChallengePageGzip_ThePageWithTheScriptInside(t *testing.T) {
	h := newTestHandler(t)
	hdr := throughModuleGzip()
	hdr["Cookie"] = scriptInPageCookie + "=1"
	rr := askPage(t, h, "203.0.113.121", "/unmask/challenge/", hdr)
	page := compressedPage(t, rr)
	if scriptFileTagRE.MatchString(page) || !strings.Contains(page, "_bv_set_ok") {
		t.Error("the decoded page is not the one with the script inside")
	}
	if rr.Body.Len()*100 > len(page)*45 {
		t.Errorf("%d bytes for a page of %d", rr.Body.Len(), len(page))
	}
}

// TestChallengePageGzip_EverySlotTaken: a serve that finds every slot taken
// sends the page as it is, and the next one after a slot is free is
// compressed again.  (The slots are what keeps a flood of serves from
// spending every processor on compression.)
func TestChallengePageGzip_EverySlotTaken(t *testing.T) {
	h := newTestHandler(t)
	for i := 0; i < cap(pageGzipSlots); i++ {
		pageGzipSlots <- struct{}{}
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		for i := 0; i < cap(pageGzipSlots); i++ {
			<-pageGzipSlots
		}
	}
	defer release()
	plainPage(t, askPage(t, h, "203.0.113.131", "/unmask/challenge/", throughModuleGzip()))
	release()
	compressedPage(t, askPage(t, h, "203.0.113.132", "/unmask/challenge/", throughModuleGzip()))
}

func TestPageGzipConcurrency(t *testing.T) {
	for procs, want := range map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 2, 8: 4, 64: 32} {
		if got := pageGzipConcurrency(procs); got != want {
			t.Errorf("%d processors: %d at once, want %d", procs, got, want)
		}
	}
	if cap(pageGzipSlots) < 1 {
		t.Fatal("no slot at all: no page would ever be compressed")
	}
}

// TestGzipPage_WhatIsDecodedIsWhatWasGiven: the writers are reused from one
// page to the next, and a page must never carry a byte of the one before.
// Pages of different sizes, one after another and at once.
func TestGzipPage_WhatIsDecodedIsWhatWasGiven(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	body := func(i int) []byte {
		var b bytes.Buffer
		for n := 0; b.Len() < 2000+(i%7)*9000; n++ {
			fmt.Fprintf(&b, "<p class=\"row-%d\">serve %d line %d of the page</p>\n", i, i, n)
		}
		return b.Bytes()
	}
	check := func(i int) error {
		src := body(i)
		// A slot may be taken by another goroutine of this test: ask again.
		for try := 0; try < 2000; try++ {
			out, ok := gzipPage(req, src)
			if !ok {
				time.Sleep(time.Millisecond)
				continue
			}
			zr, err := gzip.NewReader(bytes.NewReader(out))
			if err != nil {
				return fmt.Errorf("page %d: %v", i, err)
			}
			got, err := io.ReadAll(zr)
			if err != nil {
				return fmt.Errorf("page %d: %v", i, err)
			}
			if !bytes.Equal(got, src) {
				return fmt.Errorf("page %d: %d bytes decoded, %d given, and they differ", i, len(got), len(src))
			}
			return nil
		}
		return fmt.Errorf("page %d: never found a slot", i)
	}
	for i := 0; i < 40; i++ {
		if err := check(i); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				if err := check(g*8 + i); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Too small to gain, and a client that does not read gzip: not compressed.
	if _, ok := gzipPage(req, []byte("<p>short</p>")); ok {
		t.Error("a page of a dozen bytes was compressed")
	}
	plain := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	if _, ok := gzipPage(plain, body(3)); ok {
		t.Error("a page was compressed for a client that said nothing about gzip")
	}
}
