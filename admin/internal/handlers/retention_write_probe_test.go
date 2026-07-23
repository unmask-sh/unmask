package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The retention tab's write-health probe must tell a daemon that can read but
// not write its DB from a healthy one.  Regression target: a root-owned
// unmask.sqlite (left behind by running `unmask migrate` as root) keeps
// serving challenges while silently recording nothing — invisible from every
// dashboard until this probe.
func TestRetentionWriteProbe(t *testing.T) {
	t.Run("healthy_db_reports_ok", func(t *testing.T) {
		h := newTestHandler(t)
		v := h.retentionStats(context.Background(), nil)
		if !v.WriteChecked || !v.WriteOK {
			t.Fatalf("healthy DB: want WriteChecked+WriteOK, got checked=%v ok=%v err=%q",
				v.WriteChecked, v.WriteOK, v.WriteErr)
		}
		if v.DaemonUser == "" {
			t.Error("healthy DB: DaemonUser should resolve to the test process user")
		}
	})

	t.Run("readonly_db_reports_ng_with_fix", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: file permissions do not apply")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "unmask.sqlite")
		d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Migrate(d); err != nil {
			t.Fatal(err)
		}
		d.Close()
		// Reproduce the root-owned-file layout exactly: the DIRECTORY stays
		// writable (the daemon can create its own -wal/-shm, so it starts and
		// reads fine) while the MAIN file is not writable -- which is what a
		// root:root 0644 unmask.sqlite looks like to the unmask user.
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(path, 0o644) })

		ro, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
		if err != nil {
			t.Skipf("driver refuses to open a read-only DB outright (%v) -- probe unreachable", err)
		}
		t.Cleanup(func() { ro.Close() })
		h := &Handler{DB: ro}
		h.SetSettings(settings.Settings{DB: settings.DB{Driver: "sqlite", SQLitePath: path}})
		v := h.retentionStats(context.Background(), nil)
		if !v.WriteChecked || v.WriteOK {
			t.Fatalf("readonly DB: want WriteChecked && !WriteOK, got checked=%v ok=%v",
				v.WriteChecked, v.WriteOK)
		}
		if v.WriteErr == "" {
			t.Error("readonly DB: WriteErr should carry the driver error")
		}
		if !strings.Contains(v.FixCmd, "chown") || !strings.Contains(v.FixCmd, path) {
			t.Errorf("readonly DB: FixCmd should suggest chown of %s, got %q", path, v.FixCmd)
		}
	})

	t.Run("retention_tab_renders_probe_row", func(t *testing.T) {
		h := newTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=retention", nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("retention tab: want 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "Write check") && !strings.Contains(body, "書き込みチェック") {
			t.Error("retention tab must render the write-check row")
		}
		if !strings.Contains(body, "writable by the daemon") && !strings.Contains(body, "書き込み可能") {
			t.Error("retention tab must render the OK state for a healthy test DB")
		}
	})
}
