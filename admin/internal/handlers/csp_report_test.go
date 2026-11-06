package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// chromeReport is the body a browser posts to a report-uri, with the values
// a test wants in it.
func chromeReport(document, directive, blocked, sample string, line int) string {
	return fmt.Sprintf(`{"csp-report":{"document-uri":%q,"referrer":"","violated-directive":%q,"effective-directive":%q,`+
		`"original-policy":"frame-ancestors 'none'; script-src 'self' 'nonce-abc'","disposition":"enforce","blocked-uri":%q,`+
		`"line-number":%d,"column-number":7,"source-file":%q,"status-code":200,"script-sample":%q}}`,
		document, directive, directive, blocked, line, document, sample)
}

// postCSPReport sends body the way the browser does: to the route as the
// router wraps it, with no session and no CSRF token.
func postCSPReport(h *Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/csp-report")
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(h.AdminCSPReport)(rr, req)
	return rr
}

// cspLogLines: the report lines in what the handler logged.
func cspLogLines(logged *bytes.Buffer) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(logged.String(), "\n"), "\n") {
		if strings.HasPrefix(l, cspReportLogPrefix) {
			out = append(out, l)
		}
	}
	return out
}

// A report is one log line that says which page lost what, where, and how
// the refused script begins -- from a browser that has no session and sends
// no CSRF token.  The query of the page's address stays out of the log (a
// reset link carries its token there), and nothing in the report can start a
// line of its own.
func TestAdminCSPReportIsOneLogLine(t *testing.T) {
	h := installedHandler(t)
	var logged bytes.Buffer
	defer captureLog(&logged)()

	rr := postCSPReport(h, chromeReport("https://admin.example/unmask/admin/reset-password?token=SECRET-TOKEN#top",
		"script-src-attr", "inline", "dismissHuntTip('x')\nadmin IP denied: ip=forged", 621))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", rr.Code, rr.Body.String())
	}
	lines := cspLogLines(&logged)
	if len(lines) != 1 || strings.Count(logged.String(), "\n") != 1 {
		t.Fatalf("logged %d report line(s) in %q, want exactly one line", len(lines), logged.String())
	}
	want := cspReportLogPrefix + " page=https://admin.example/unmask/admin/reset-password directive=script-src-attr blocked=inline" +
		" at=https://admin.example/unmask/admin/reset-password:621:7 ip=203.0.113.9 session=no" +
		` sample=dismissHuntTip('x')\nadmin IP denied: ip=forged`
	if lines[0] != want {
		t.Errorf("line:\n got %s\nwant %s", lines[0], want)
	}
	if strings.Contains(logged.String(), "SECRET-TOKEN") {
		t.Error("the page's query string reached the log")
	}

	// From a signed-in browser the line says so; and a value longer than
	// the cut is cut.
	logged.Reset()
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/csp-report",
		strings.NewReader(chromeReport("https://admin.example/unmask/admin/hunt/", "script-src-elem", "https://cdn.example/x.js?v=1", strings.Repeat("é", 400), 1)))
	req.AddCookie(issueSessionCookie(h.adminSecret(), "/unmask", 1, "superadmin", false, false, 0))
	rr = httptest.NewRecorder()
	h.AdminIPAllowMiddleware(h.AdminCSPReport)(rr, req)
	lines = cspLogLines(&logged)
	if rr.Code != http.StatusNoContent || len(lines) != 1 {
		t.Fatalf("signed-in report: status %d, %d line(s)", rr.Code, len(lines))
	}
	for _, part := range []string{" session=yes ", " blocked=https://cdn.example/x.js ", " sample=" + strings.Repeat("é", cspReportFieldMax/2) + "..."} {
		if !strings.Contains(lines[0]+" ", part) {
			t.Errorf("line lacks %q: %s", part, lines[0])
		}
	}
	if len(lines[0]) > 600 {
		t.Errorf("a %d-byte line from a long sample; the cut did not hold", len(lines[0]))
	}
}

// What is not a report is refused and leaves no line: a body over the cap, a
// body that is not the browser's document.
func TestAdminCSPReportRefusesWhatIsNotAReport(t *testing.T) {
	h := installedHandler(t)
	var logged bytes.Buffer
	defer captureLog(&logged)()

	big := chromeReport("https://admin.example/unmask/admin/", "script-src-elem", "inline", strings.Repeat("x", cspReportMaxBody), 1)
	if rr := postCSPReport(h, big); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a %d-byte body: status %d, want 413", len(big), rr.Code)
	}
	for _, body := range []string{"", "not json", `{}`, `{"csp-report":null}`, `[{"type":"csp-violation"}]`} {
		if rr := postCSPReport(h, body); rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rr.Code)
		}
	}
	if logged.Len() != 0 {
		t.Errorf("a refused body was logged: %q", logged.String())
	}
	// Just under the cap is a report like any other.
	fits := chromeReport("https://admin.example/unmask/admin/", "script-src-elem", "inline", strings.Repeat("x", cspReportMaxBody-600), 1)
	if rr := postCSPReport(h, fits); rr.Code != http.StatusNoContent || len(cspLogLines(&logged)) != 1 {
		t.Errorf("a %d-byte report: status %d, logged %q", len(fits), rr.Code, logged.String())
	}
}

// The route is behind the address gate like the login page: a browser the
// allowlist turns away cannot write to the log either.
func TestAdminCSPReportIsBehindTheAddressGate(t *testing.T) {
	h := installedHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Nginx.AdminAllowedIPs = []string{"192.0.2.0/24"} })
	var logged bytes.Buffer
	defer captureLog(&logged)()
	rr := postCSPReport(h, chromeReport("https://admin.example/unmask/admin/", "script-src-elem", "inline", "x", 1))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d from an address outside the allowlist, want 403", rr.Code)
	}
	if n := len(cspLogLines(&logged)); n != 0 {
		t.Errorf("%d report line(s) from an address outside the allowlist", n)
	}
}

// A page that lost its nonce reports every script on every load.  The lines
// stop at cspReportLinesPerMinute a minute; the rest are counted, and the
// count is one line when the minute ends -- with or without another report
// to bring it out.
func TestAdminCSPReportLinesAreRationed(t *testing.T) {
	h := installedHandler(t)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	var timers []func()
	var waits []time.Duration
	h.cspReports.now = func() time.Time { return now }
	h.cspReports.after = func(d time.Duration, f func()) { waits = append(waits, d); timers = append(timers, f) }
	var logged bytes.Buffer
	defer captureLog(&logged)()
	report := chromeReport("https://admin.example/unmask/admin/", "script-src-elem", "inline", "x", 1)

	const extra = 7
	for i := 0; i < cspReportLinesPerMinute+extra; i++ {
		if rr := postCSPReport(h, report); rr.Code != http.StatusNoContent {
			t.Fatalf("report %d: status %d", i, rr.Code)
		}
		now = now.Add(time.Second)
	}
	if n := len(cspLogLines(&logged)); n != cspReportLinesPerMinute {
		t.Fatalf("%d lines in one minute, want %d", n, cspReportLinesPerMinute)
	}
	// One timer, set by the first report over the ration, for the rest of
	// the minute.
	if len(timers) != 1 || waits[0] != time.Minute-time.Duration(cspReportLinesPerMinute)*time.Second {
		t.Fatalf("timers: %d, waits %v", len(timers), waits)
	}
	timers[0]()
	lines := cspLogLines(&logged)
	if last := lines[len(lines)-1]; len(lines) != cspReportLinesPerMinute+1 || last != fmt.Sprintf("%s suppressed %d more reports (over %d a minute)", cspReportLogPrefix, extra, cspReportLinesPerMinute) {
		t.Fatalf("after the minute: %d lines, the last %q", len(lines), last)
	}
	// Said once.
	timers[0]()
	if n := len(cspLogLines(&logged)); n != cspReportLinesPerMinute+1 {
		t.Errorf("the count was logged again: %d lines", n)
	}

	// A new minute starts a new ration; a count still held when its first
	// report arrives is written ahead of it.
	logged.Reset()
	now = now.Add(2 * time.Minute)
	for i := 0; i < cspReportLinesPerMinute+2; i++ {
		postCSPReport(h, report)
	}
	now = now.Add(2 * time.Minute)
	postCSPReport(h, report)
	lines = cspLogLines(&logged)
	if len(lines) != cspReportLinesPerMinute+2 || !strings.Contains(lines[cspReportLinesPerMinute], "suppressed 2 more reports") || !strings.Contains(lines[cspReportLinesPerMinute+1], " page=") {
		t.Errorf("the next minutes: %d lines, the last two %q", len(lines), lines[max(0, len(lines)-2):])
	}
}
