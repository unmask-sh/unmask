package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The admin UI is a protected path by default, so a password-reset or
// account-setup link opened in a browser with no pass meets the challenge,
// and the serve is recorded with the page that was asked for.  The link's
// token was in that row -- and the token alone sets the password -- where
// every role reads it: the hunt page, the live tail, the AI tools.  A viewer
// could set an invited superadmin's password first.  The row now names the
// page without its query, on the serve and on the beacons the page sends.
func TestResetLinkTokenStaysOutOfTheEventLog(t *testing.T) {
	h := newTestHandler(t)
	const tok = "5f2c9a1e7b3d4c6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"
	link := "/unmask/admin/reset-password?token=" + tok
	payloads := func() []string {
		t.Helper()
		rows, err := h.DB.QueryContext(context.Background(), `SELECT COALESCE(payload_json, '') FROM unmask_event`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	waitRows := func(n int) []string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got := payloads()
			if len(got) >= n {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d event rows, want %d", len(got), n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// The link opened without a pass: nginx routes it to the challenge with
	// the page asked for in X-Original-URI, as server.inc sets it.  The
	// browser came from the reset page itself (a form sent again).
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?_orig="+url.QueryEscape(link), nil)
	req.Header.Set("User-Agent", uaCurrentChrome)
	req.Header.Set("X-Original-URI", link)
	req.Header.Set("X-Protected-Mode", "pow_then_captcha")
	req.Header.Set("Referer", "https://admin.example.com"+link)
	h.ServeChallenge(httptest.NewRecorder(), req)
	rows := waitRows(1)

	// The page's beacons echo the address it was served for.
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	breq := httptest.NewRequest(http.MethodPost, "/unmask/api/debug",
		strings.NewReader(`{"phase":"load","bt":"`+bt+`","orig_path":"`+link+`","url":"https://admin.example.com`+link+`"}`))
	breq.Header.Set("Content-Type", "application/json")
	breq.Header.Set("X-Real-IP", "198.51.100.7")
	brr := httptest.NewRecorder()
	h.DebugBeacon(brr, breq)
	if brr.Code != http.StatusOK {
		t.Fatalf("the beacon: %d %s", brr.Code, brr.Body.String())
	}
	rows = waitRows(len(rows) + 1)

	named := 0
	for _, p := range rows {
		if strings.Contains(p, tok) {
			t.Errorf("the token is in the event log: %s", p)
		}
		if strings.Contains(p, `"orig_path":"/unmask/admin/reset-password"`) {
			named++
		}
	}
	if named < 2 {
		t.Errorf("%d of %d rows name the page without its query, want the serve and the beacon:\n%s", named, len(rows), strings.Join(rows, "\n"))
	}
}
