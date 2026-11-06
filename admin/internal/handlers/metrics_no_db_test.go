package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// scrapeMetrics is one scrape from loopback.
func scrapeMetrics(h *Handler) (int, string) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/metrics", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	rr := httptest.NewRecorder()
	h.Metrics(rr, r)
	return rr.Code, rr.Body.String()
}

// /metrics answers on a daemon without its database -- the scrape used to
// die in a nil dereference -- with unmask_db_up 0, what it reads from memory
// and disk, and nothing it would have read from the database.
func TestMetricsWithoutDatabase(t *testing.T) {
	h := &Handler{}
	h.SetSettings(settings.Settings{
		Server: settings.Server{BasePath: "/unmask"},
		Nginx:  settings.Nginx{OutputDir: t.TempDir()},
	})
	code, body := scrapeMetrics(h)
	if code != http.StatusOK {
		t.Fatalf("scrape without a database: %d", code)
	}
	for _, want := range []string{
		"unmask_db_up 0\n",
		"unmask_native_failsafe_active 0\n",
		"unmask_nginx_config_stale 0\n",
		"unmask_verify_score_count ",
		"unmask_events_dropped_total 0\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape lacks %q", strings.TrimSpace(want))
		}
	}
	for _, absent := range []string{"unmask_schema_update_pending", "unmask_event_unique_ip "} {
		if strings.Contains(body, absent) {
			t.Errorf("the scrape reports %s with no database to read it from", absent)
		}
	}

	if _, body := scrapeMetrics(newTestHandler(t)); !strings.Contains(body, "unmask_db_up 1\n") {
		t.Errorf("a daemon with its database does not say unmask_db_up 1")
	}
}
