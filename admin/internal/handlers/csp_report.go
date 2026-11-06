package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// What the browser refused under the admin's Content-Security-Policy.
//
// The policy's report-uri points here, and the browser posts one small JSON
// document per refusal: a <script> a template emitted without the nonce, an
// inline handler, a script someone managed to inject.  Each becomes one log
// line and nothing else -- no table, no notice.  The sender needs no session
// (the login page reports too) and no CSRF token (the browser posts on its
// own and has none to send), so whoever can reach the login page can post
// here: the body is capped, every quoted value is cut and made log-safe, and
// the lines are rationed.

const (
	// cspReportLogPrefix starts every line a report writes.  Fixed text: the
	// UI e2e suite fails a run whose daemon logged it (e2e/ui/run.sh).
	cspReportLogPrefix = "admin csp violation:"
	// cspReportMaxBody: a report is a few hundred bytes, most of them the
	// policy it quotes back.
	cspReportMaxBody = 16 << 10
	// cspReportLinesPerMinute: a page that lost its nonce reports every one
	// of its scripts on every load.  Past this many lines in a minute the
	// reports are counted, and the count is one line when the minute is over.
	cspReportLinesPerMinute = 20
	// cspReportFieldMax cuts each value quoted from a report.
	cspReportFieldMax = 200
)

// cspReportBody is what a browser posts to a report-uri
// (application/csp-report): one object under "csp-report".
type cspReportBody struct {
	Report *struct {
		DocumentURI        string `json:"document-uri"`
		EffectiveDirective string `json:"effective-directive"`
		ViolatedDirective  string `json:"violated-directive"`
		BlockedURI         string `json:"blocked-uri"`
		SourceFile         string `json:"source-file"`
		LineNumber         int    `json:"line-number"`
		ColumnNumber       int    `json:"column-number"`
		ScriptSample       string `json:"script-sample"`
	} `json:"csp-report"`
}

// AdminCSPReport: POST {base}/admin/csp-report -- the report-uri of the
// admin's policy.  Behind the IP/host gate only (AdminIPAllowMiddleware):
// see the note at the top of the file.
func (h *Handler) AdminCSPReport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cspReportMaxBody))
	if err != nil {
		http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
		return
	}
	var doc cspReportBody
	if err := json.Unmarshal(body, &doc); err != nil || doc.Report == nil {
		http.Error(w, "not a CSP report", http.StatusBadRequest)
		return
	}
	rep := doc.Report
	directive := rep.EffectiveDirective
	if directive == "" {
		directive = rep.ViolatedDirective
	}
	session := "no"
	if h.hasAdminSession(r) {
		session = "yes"
	}
	// The sample goes last: it is the one free-text value, and nothing after
	// it can be mistaken for part of it.
	h.cspReports.write(fmt.Sprintf("page=%s directive=%s blocked=%s at=%s:%d:%d ip=%s session=%s sample=%s",
		cspReportField(cspReportURL(rep.DocumentURI)),
		cspReportField(directive),
		cspReportField(cspReportURL(rep.BlockedURI)),
		cspReportField(cspReportURL(rep.SourceFile)), rep.LineNumber, rep.ColumnNumber,
		cspReportField(adminClientIP(r, h.snapshotSettings())),
		session,
		cspReportField(rep.ScriptSample)))
	w.WriteHeader(http.StatusNoContent)
}

// cspReportURL keeps what locates a URL a report quotes -- origin and path --
// and drops its query and fragment: a reset link's token rides the query,
// and the log is not the place for it.  A keyword in the URL's place
// ("inline", "eval") is returned as it is.
func cspReportURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Host == "" && u.Path == "") {
		raw, _, _ = strings.Cut(raw, "?")
		raw, _, _ = strings.Cut(raw, "#")
		return raw
	}
	if u.Host == "" {
		return u.Path
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// cspReportField makes one quoted value fit a log line: valid UTF-8, cut to
// cspReportFieldMax, control characters escaped (LogSafe), "-" when empty.
func cspReportField(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > cspReportFieldMax {
		cut := cspReportFieldMax
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	if s == "" {
		return "-"
	}
	return LogSafe(s)
}

// cspReportLog rations the report lines: cspReportLinesPerMinute a minute,
// then a count.  The zero value is ready.
type cspReportLog struct {
	mu         sync.Mutex
	minuteEnd  time.Time // the minute being counted ends here
	lines      int       // lines written in it
	suppressed int       // reports counted instead of written
	// The clock and the timer behind the end-of-minute count; nil means
	// time.Now and time.AfterFunc.  The tests set both.
	now   func() time.Time
	after func(time.Duration, func())
}

// write logs one report, or counts it once the minute's lines are used up.
func (l *cspReportLog) write(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	if !now.Before(l.minuteEnd) {
		l.flushLocked()
		l.minuteEnd = now.Add(time.Minute)
		l.lines = 0
	}
	if l.lines < cspReportLinesPerMinute {
		l.lines++
		log.Print(cspReportLogPrefix + " " + line)
		return
	}
	l.suppressed++
	if l.suppressed == 1 {
		// The count is written when the minute ends, whether or not another
		// report arrives to trigger it.
		wait := l.minuteEnd.Sub(now)
		if l.after != nil {
			l.after(wait, l.flush)
		} else {
			time.AfterFunc(wait, l.flush)
		}
	}
}

// flush writes the count of the reports the ration held back, if any.
func (l *cspReportLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushLocked()
}

func (l *cspReportLog) flushLocked() {
	if l.suppressed == 0 {
		return
	}
	log.Printf("%s suppressed %d more reports (over %d a minute)", cspReportLogPrefix, l.suppressed, cspReportLinesPerMinute)
	l.suppressed = 0
}
