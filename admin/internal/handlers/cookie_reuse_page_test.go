package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestStatsPageRendersPowReuse drives the real stats handler against a real
// migrated database.  The template-level test proves the markup; this proves the
// wiring between them -- a mistyped template-data key would leave .PowReuse
// empty and render the "no reuse in this period" message with no error anywhere,
// which is indistinguishable from a quiet install.
func TestStatsPageRendersPowReuse(t *testing.T) {
	conn, err := db.Open(settings.DB{
		Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.sqlite"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}

	min := time.Now().Unix() / 60
	last := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	ins := func(ip, kind, ja4 string, cnt int, off int64) {
		t.Helper()
		if _, err := conn.Exec(`INSERT INTO unmask_cookie_ip_minute
			(bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
			VALUES (?, 'default', ?, ?, ?, 'ProbeUA/1.0', ?, ?)`,
			min-off, events.PackIP(ip), kind, ja4, cnt, last); err != nil {
			t.Fatal(err)
		}
	}
	ins("203.0.113.5", "captcha", "t13d_cap", 120, 1)
	// One IP on a single fingerprint (the scraper shape) and one spread across
	// several (the shared-egress shape), so the rendered page has to show both.
	ins("198.51.100.20", "pow", "t13d_solo", 4000, 1)
	for i, ja4 := range []string{"t13d_p", "t13d_q", "t13d_r"} {
		ins("198.51.100.21", "pow", ja4, 300, int64(i+1))
	}

	h := &Handler{DB: conn}
	h.SetSettings(settings.Settings{})

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	h.AdminStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats page status %d", rr.Code)
	}
	body := rr.Body.String()

	// Both rankings reached the page from the database.
	if !strings.Contains(body, "203.0.113.5") {
		t.Error("the CAPTCHA reuse row is missing from the rendered page")
	}
	if !strings.Contains(body, "198.51.100.20") || !strings.Contains(body, "198.51.100.21") {
		t.Error("the PoW reuse rows are missing -- the handler is not feeding the section")
	}
	// The empty-state message must not be showing for PoW when rows exist; that
	// is exactly what a broken template-data key looks like.
	if strings.Contains(body, "期間内に PoW cookie の使い回しアクセスはありません") {
		t.Error("the PoW section rendered its empty state despite having rows")
	}
	// The fingerprint-spread column carries real counts, not a placeholder.
	if !strings.Contains(body, "cr-ja4n-single") {
		t.Error("the single-fingerprint row is not marked; JA4Count did not survive the query")
	}
	if !strings.Contains(body, ">3<") {
		t.Error("the three-fingerprint count is not rendered")
	}
}
