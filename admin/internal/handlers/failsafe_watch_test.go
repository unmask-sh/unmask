package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/banfile"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/notice"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// failsafeHandler: an installed handler with a notification store, rendering
// into a scratch dir.
func failsafeHandler(t *testing.T, dir string) *Handler {
	t.Helper()
	h := installedHandler(t)
	st := *h.cfg()
	st.Server.BasePath = "/unmask"
	st.Nginx.OutputDir = dir
	h.SetSettings(st)
	h.Notices = notice.New(h.DB)
	return h
}

func failsafeRows(t *testing.T, h *Handler) []notice.Entry {
	t.Helper()
	rows, err := h.Notices.List(context.Background(), 1, notice.KindFailsafe, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// The watch writes a row when the plugin's fail-safe marker appears (crit,
// with the cause place-module wrote) and one when it goes (info) -- never
// one per look, and nothing on a healthy install.  A daemon restart in
// either state adds nothing: the list's last row already says it.
func TestFailsafeWatchNoticesTheMarkerComingAndGoing(t *testing.T) {
	dir := t.TempDir()
	h := failsafeHandler(t, dir)
	ctx := context.Background()
	marker := filepath.Join(dir, nginxconf.FailsafeMarker)

	h.failsafeTick(ctx)
	h.failsafeTick(ctx)
	if rows := failsafeRows(t, h); len(rows) != 0 {
		t.Fatalf("a healthy install got %d row(s): %+v", len(rows), rows)
	}

	if err := os.WriteFile(marker, []byte("native wiring stripped by place-module fail-safe\nreason: no bundled module for host nginx 1.99.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.failsafeTick(ctx)
	h.failsafeTick(ctx)
	rows := failsafeRows(t, h)
	if len(rows) != 1 || !rows[0].Bool("active") || rows[0].Severity != notice.SeverityCrit ||
		rows[0].Str("reason") != "no bundled module for host nginx 1.99.0" || rows[0].Int("since") == 0 {
		t.Fatalf("after the marker appeared: %+v", rows)
	}

	// A restart while the marker is there: the last row says active, so
	// nothing is added.
	h2 := failsafeHandler(t, dir)
	h2.DB, h2.Notices = h.DB, h.Notices
	h2.failsafeTick(ctx)
	if rows := failsafeRows(t, h2); len(rows) != 1 {
		t.Fatalf("a restart under the marker added a row: %+v", rows)
	}

	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	h.failsafeTick(ctx)
	h.failsafeTick(ctx)
	rows = failsafeRows(t, h)
	if len(rows) != 2 || rows[0].Bool("active") || rows[0].Severity != notice.SeverityInfo || !rows[1].Bool("active") {
		t.Fatalf("after the marker went: %+v", rows)
	}

	// A restart on the healthy install with a cleared row on record: nothing.
	h3 := failsafeHandler(t, dir)
	h3.DB, h3.Notices = h.DB, h.Notices
	h3.failsafeTick(ctx)
	if rows := failsafeRows(t, h3); len(rows) != 2 {
		t.Fatalf("a restart after the clearing added a row: %+v", rows)
	}

	// The rows read in the operator's words, on the page and in the panel.
	req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/notices/?kind=native_failsafe", nil), user.RoleAdmin)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminNoticesIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("notices page: %d %s", rr.Code, rr.Body.String())
	}
	page := rr.Body.String()
	for _, want := range []string{
		"The unmask nginx module is not loaded; protection is off",
		"Cause: no bundled module for host nginx 1.99.0",
		"The unmask nginx module is back; protection resumes",
		`href="/unmask/admin/settings/about/"`,
		`class="sev sev-crit"`, `class="sev sev-info"`,
		">nginx module off<",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the notices page lacks %q", want)
		}
	}
	if strings.Contains(page, "notice.failsafe.") || strings.Contains(page, "notice.kind.native_failsafe") {
		t.Error("the notices page shows a raw key")
	}
}

// The three state gauges: the fail-safe marker, the reload marker, and the
// ban list nginx's worker reads -- each from the install's own files, so an
// alert rule can watch them.
func TestMetricsStateGauges(t *testing.T) {
	dir := t.TempDir()
	h := newTestHandler(t)
	st := *h.cfg()
	st.Nginx.OutputDir = dir
	h.SetSettings(st)
	h.BanFileCheck = func() banfile.Verdict { return banfile.Verdict{OK: true} }

	scrape := func() string {
		t.Helper()
		h.banFileMu.Lock()
		h.banFileAt = time.Time{} // the notice keeps a verdict for a while; read it again
		h.banFileMu.Unlock()
		r := httptest.NewRequest(http.MethodGet, "/unmask/metrics", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		rr := httptest.NewRecorder()
		h.Metrics(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("metrics: %d", rr.Code)
		}
		return rr.Body.String()
	}
	want := func(body string, lines ...string) {
		t.Helper()
		for _, ln := range lines {
			if !strings.Contains(body, ln+"\n") {
				t.Errorf("metrics lack %q", ln)
			}
		}
	}

	body := scrape()
	want(body,
		"# TYPE unmask_native_failsafe_active gauge", "unmask_native_failsafe_active 0",
		"# TYPE unmask_nginx_config_stale gauge", "unmask_nginx_config_stale 0",
		"# TYPE unmask_ban_file_worker_readable gauge", "unmask_ban_file_worker_readable 1",
		"# TYPE unmask_nginxlog_dropped_total counter", "unmask_nginxlog_dropped_total 0",
		"# TYPE unmask_events_bad_rows_total counter", "unmask_events_bad_rows_total 0",
		"# TYPE unmask_events_dropped_total counter", "unmask_events_dropped_total 0")

	if err := os.WriteFile(filepath.Join(dir, nginxconf.FailsafeMarker), []byte("reason: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nginxconf.ReloadNeededMarker), []byte("0123456789ab\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.BanFileCheck = func() banfile.Verdict {
		return banfile.Verdict{User: "nginx", Blocker: "/var/lib/unmask", Need: "x"}
	}
	want(scrape(), "unmask_native_failsafe_active 1", "unmask_nginx_config_stale 1", "unmask_ban_file_worker_readable 0")

	if !nginxconf.ClearReloadNeeded(dir, "0123456789ab") {
		t.Fatal("the reload marker was not cleared")
	}
	want(scrape(), "unmask_nginx_config_stale 0")
}
