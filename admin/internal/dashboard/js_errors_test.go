package dashboard

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// The JavaScript errors card splits error-phase rows into the challenge's own
// failures (the table) and foreign-script noise (the folded list).  Rows
// stored before challenge.js counted the page's own URL at line 1 as foreign
// carry kind=js_exception; the card must still fold them, or every Brave
// visit on iOS reads as a broken challenge.
func TestJSErrorsSplitOwnFromForeign(t *testing.T) {
	d := openTestDB(t)
	page := "https://example.jp/a/"
	for i, p := range []string{
		// Brave on iOS, captured before the line-1 rule: the wallet's
		// evaluateJavaScript, reported against the page URL at line 1.
		`{"kind":"js_exception","error_msg":"TypeError: undefined is not an object (evaluating 'window.ethereum.selectedAddress = undefined')","error_filename":"` + page + `","error_lineno":1}`,
		// The same, captured after it.
		`{"kind":"js_foreign","error_msg":"TypeError: undefined is not an object (evaluating 'window.ethereum.emit')","error_filename":"` + page + `","error_lineno":1}`,
		`{"kind":"js_foreign","error_msg":"Script error.","error_filename":"","error_lineno":0}`,
		// The challenge's own failures: the inlined script further down the
		// page, the external asset (line 1 there is still unmask's), and a
		// CAPTCHA provider that would not render.
		`{"kind":"js_exception","error_msg":"TypeError: solve is not a function","error_filename":"` + page + `","error_lineno":412}`,
		`{"kind":"js_exception","error_msg":"SyntaxError: Unexpected end of input","error_filename":"https://example.jp/unmask/static/challenge.js?v=1","error_lineno":1}`,
		`{"kind":"ext_render_err","provider":"turnstile","error":"render failed"}`,
	} {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','','','UA','','',0,'error',0,0,'','',?,datetime('now','-30 minutes'))`,
			p); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
	ctx := context.Background()

	own, err := JSErrors(ctx, d, "", nil, 24)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := errText(own), []string{"", "SyntaxError: Unexpected end of input", "TypeError: solve is not a function"}; !equalStrings(got, want) {
		t.Errorf("own errors = %q, want %q", got, want)
	}

	foreign, err := JSForeignErrors(ctx, d, "", nil, 24)
	if err != nil {
		t.Fatal(err)
	}
	if got := errText(foreign); len(got) != 3 || !strings.Contains(strings.Join(got, "|"), "window.ethereum.selectedAddress") {
		t.Errorf("foreign errors = %q, want the three foreign rows including the pre-rule ethereum one", got)
	}
	if n, err := JSForeignErrorCount(ctx, d, "", nil, 24); err != nil || n != 3 {
		t.Errorf("foreign count = %d (%v), want 3", n, err)
	}
}

func errText(rows []JSErrorRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Error)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
