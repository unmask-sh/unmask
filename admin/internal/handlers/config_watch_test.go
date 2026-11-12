package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// watchedHandler is a daemon as it stands after its start: a config.yml on
// disk, the live settings read from it, the file's signature taken.
func watchedHandler(t *testing.T) *Handler {
	t.Helper()
	h := installedHandler(t)
	dir := t.TempDir()
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Secret.CaptchaSecretBase = "test-captcha-secret"
	s.Nginx.OutputDir = filepath.Join(dir, "nginx")
	h.ConfigPath = filepath.Join(dir, "config.yml")
	if err := settings.Save(s, h.ConfigPath); err != nil {
		t.Fatal(err)
	}
	sig := settings.FileSignature(h.ConfigPath)
	live, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(live)
	h.SetConfigSignature(sig)
	return h
}

// writtenOutside changes config.yml the way another process does: under the
// file's lock, without the daemon's handler hearing of it.
func writtenOutside(t *testing.T, h *Handler, fn func(*settings.Settings)) {
	t.Helper()
	if err := settings.Update(h.ConfigPath, func(s *settings.Settings) error { fn(s); return nil }); err != nil {
		t.Fatal(err)
	}
}

func fileAuditRows(t *testing.T, h *Handler) (n int, lastDetail string) {
	t.Helper()
	rows, err := h.DB.Query(`SELECT COALESCE(detail, '') FROM unmask_user_audit WHERE action = 'settings_save' AND username = ? AND target = '_file' ORDER BY id`, user.ConfigFileActor)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&lastDetail); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n, lastDetail
}

// A config.yml changed by someone other than the daemon -- the CLI's
// upgrade-review, an edit -- is adopted: the live settings, nginx's rendered
// configuration and the audit log all follow, at the second look that finds
// the file as it was.  Until then the daemon judged by what it had read at
// its start, and its next render of its own wrote that back over the file's.
func TestConfigWatchAdoptsAFileChangedOutsideTheAdmin(t *testing.T) {
	h := watchedHandler(t)
	ctx := context.Background()

	// Nothing has changed: looks do nothing.
	h.configWatchTick(ctx)
	h.configWatchTick(ctx)
	if n, _ := fileAuditRows(t, h); n != 0 {
		t.Fatalf("an unchanged file was adopted (%d audit rows)", n)
	}

	writtenOutside(t, h, func(s *settings.Settings) {
		s.Nginx.BypassIPs = append(s.Nginx.BypassIPs, "203.0.113.9")
	})
	h.configWatchTick(ctx) // seen once: a writer may still be at it
	if got := h.cfg().Nginx.BypassIPs; len(got) != 0 {
		t.Fatalf("adopted at the first look: %v", got)
	}
	h.configWatchTick(ctx) // the same at the second look: adopted
	if got := h.cfg().Nginx.BypassIPs; len(got) != 1 || got[0] != "203.0.113.9" {
		t.Fatalf("live bypass_ips = %v, want the file's", got)
	}

	// nginx's configuration is rendered from the adopted settings, and the
	// record beside it says why.
	out := h.cfg().Nginx.OutputDir
	httpInc, err := os.ReadFile(filepath.Join(out, "http.inc"))
	if err != nil {
		t.Fatalf("no render after the adoption: %v", err)
	}
	if !strings.Contains(string(httpInc), "203.0.113.9") {
		t.Error("the rendered http.inc does not carry the file's bypass address")
	}
	rec, ok := nginxconf.ReadRenderRecord(out)
	if !ok || rec.Cause.Kind != nginxconf.RenderByConfigFile {
		t.Errorf("render record: ok=%v cause=%+v, want %s", ok, rec.Cause, nginxconf.RenderByConfigFile)
	}

	// The audit log has the change, under the file's name, with its diff.
	n, detail := fileAuditRows(t, h)
	if n != 1 {
		t.Fatalf("%d audit rows for the adoption, want 1", n)
	}
	if !strings.Contains(detail, "203.0.113.9") {
		t.Errorf("the audit row's detail does not carry the change: %.200s", detail)
	}

	// Looked at again, the adopted file is the known one.
	h.configWatchTick(ctx)
	h.configWatchTick(ctx)
	if n, _ := fileAuditRows(t, h); n != 1 {
		t.Errorf("the adopted file was adopted again (%d audit rows)", n)
	}
}

// The daemon's own save is not read back: it is published by the save, with
// the saver's name in the audit log.
func TestConfigWatchLeavesTheDaemonsOwnSaveAlone(t *testing.T) {
	h := watchedHandler(t)
	ctx := context.Background()
	if _, err := h.mutateSettings(func(s *settings.Settings) error {
		s.Nginx.BypassIPs = append(s.Nginx.BypassIPs, "198.51.100.4")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		h.configWatchTick(ctx)
	}
	if n, _ := fileAuditRows(t, h); n != 0 {
		t.Errorf("the daemon's own save was adopted as a change of the file (%d audit rows)", n)
	}
	if _, err := os.Stat(filepath.Join(h.cfg().Nginx.OutputDir, "http.inc")); err == nil {
		t.Error("the watch rendered for the daemon's own save")
	}
}

// A file that is touched, or whose comments change, holds the same settings:
// read once, not adopted.
func TestConfigWatchReadsATouchedFileAndChangesNothing(t *testing.T) {
	h := watchedHandler(t)
	ctx := context.Background()
	before := h.cfg()
	body, err := os.ReadFile(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.ConfigPath, append([]byte("# a note by the operator\n"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	h.configWatchTick(ctx)
	h.configWatchTick(ctx)
	if h.cfg() != before {
		t.Error("the live settings were replaced for a comment")
	}
	if n, _ := fileAuditRows(t, h); n != 0 {
		t.Errorf("a comment was audited as a change (%d rows)", n)
	}
	h.cfgWatch.mu.Lock()
	known := h.cfgWatch.known
	h.cfgWatch.mu.Unlock()
	if known != settings.FileSignature(h.ConfigPath) {
		t.Error("the touched file is not the known one: it would be read at every look")
	}
}

// A writer still at work is waited out, and a file that does not load is
// left alone -- once -- until it changes again.
func TestConfigWatchWaitsOutAWriterAndKeepsWhatLoads(t *testing.T) {
	h := watchedHandler(t)
	ctx := context.Background()

	writtenOutside(t, h, func(s *settings.Settings) { s.Nginx.BypassIPs = []string{"203.0.113.1"} })
	h.configWatchTick(ctx)
	writtenOutside(t, h, func(s *settings.Settings) { s.Nginx.BypassIPs = []string{"203.0.113.1", "203.0.113.2"} })
	h.configWatchTick(ctx) // changed again since the last look: still waiting
	if got := h.cfg().Nginx.BypassIPs; len(got) != 0 {
		t.Fatalf("adopted while the file was still changing: %v", got)
	}
	h.configWatchTick(ctx)
	if got := h.cfg().Nginx.BypassIPs; len(got) != 2 {
		t.Fatalf("live bypass_ips = %v, want the file's two", got)
	}

	// Half an edit: not YAML.
	good, err := os.ReadFile(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.ConfigPath, []byte("nginx:\n  bypass_ips: [\"203.0.113.3\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.configWatchTick(ctx)
	h.configWatchTick(ctx)
	if got := h.cfg().Nginx.BypassIPs; len(got) != 2 {
		t.Fatalf("a file that does not load replaced the settings: %v", got)
	}
	h.cfgWatch.mu.Lock()
	refused := h.cfgWatch.refused
	h.cfgWatch.mu.Unlock()
	if refused != settings.FileSignature(h.ConfigPath) {
		t.Error("the file that does not load is not marked: it would be read, and said, at every look")
	}

	// The edit finished.  (A later time: the two writes above can share one.)
	fixed := strings.Replace(string(good), "203.0.113.2", "203.0.113.4", 1)
	if err := os.WriteFile(h.ConfigPath, []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(h.ConfigPath, later, later); err != nil {
		t.Fatal(err)
	}
	h.configWatchTick(ctx)
	h.configWatchTick(ctx)
	if got := h.cfg().Nginx.BypassIPs; len(got) != 2 || got[1] != "203.0.113.4" {
		t.Fatalf("live bypass_ips = %v, want the finished edit", got)
	}
}
