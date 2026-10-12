package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// fakeProcWorkers: a /proc-shaped tree with a btime and nginx workers whose
// starttime fields place their start at the given moments.
func fakeProcWorkers(t *testing.T, btime int64, workerStarts []time.Time) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte(fmt.Sprintf("cpu  0 0 0 0\nbtime %d\n", btime)), 0o644); err != nil {
		t.Fatal(err)
	}
	for i, st := range workerStarts {
		dir := filepath.Join(root, fmt.Sprint(1000+i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"),
			[]byte(strings.ReplaceAll("nginx: worker process", " ", "\x00")+"\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
		ticks := (st.Unix() - btime) * 100
		// comm carries a space + parenthesis on purpose: field counting must
		// anchor on the LAST ')' or every later field is off by one.
		stat := fmt.Sprintf("%d (nginx: work) S 1 1 1 0 -1 4194624 100 0 0 0 5 5 0 0 20 0 1 0 %d 1000000 100", 1000+i, ticks)
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// The field report that motivated this check: http.inc rendered at 12:24:56,
// workers started 11:17:21, and every doctor line was green for the twelve
// minutes the saved settings were not live.
func TestCheckNginxReloadLag(t *testing.T) {
	// The check reads the marker Render writes when a file actually changed --
	// never the .inc mtimes, which a package upgrade refreshes on a config
	// that did not move (that read called all seven fleet nodes stale).
	renderDir := func(mtime time.Time) settings.Settings {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "http.inc"), []byte("# rendered"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, nginxconf.SubstantiveRenderMarker)
		if err := os.WriteFile(p, []byte("2026-08-06T00:00:00Z\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		s := settings.Settings{}
		s.Nginx.OutputDir = dir
		return s
	}
	run := func(s settings.Settings) (ok, warn []string) {
		checkNginxReloadLag(s,
			func(_, m string) { ok = append(ok, m) },
			func(_, m string) { warn = append(warn, m) })
		return
	}

	btime := time.Date(2026, 8, 6, 0, 0, 0, 0, time.Local).Unix()
	loaded := time.Date(2026, 8, 6, 11, 17, 21, 0, time.Local)

	t.Run("rendered after the reload -> WARN", func(t *testing.T) {
		fakeProcWorkers(t, btime, []time.Time{loaded})
		_, warn := run(renderDir(time.Date(2026, 8, 6, 12, 24, 56, 0, time.Local)))
		if len(warn) != 1 {
			t.Fatalf("want 1 warning, got %v", warn)
		}
		if !strings.Contains(warn[0], "NOT live") || !strings.Contains(warn[0], "reload") {
			t.Fatalf("warning must say the render is not live and how to apply it: %s", warn[0])
		}
	})

	t.Run("reloaded after the render -> OK", func(t *testing.T) {
		fakeProcWorkers(t, btime, []time.Time{loaded})
		ok, warn := run(renderDir(loaded.Add(-10 * time.Minute)))
		if len(warn) != 0 || len(ok) != 1 {
			t.Fatalf("want clean OK, got ok=%v warn=%v", ok, warn)
		}
	})

	t.Run("draining old worker beside fresh ones stays OK", func(t *testing.T) {
		// Mid-reload nginx runs old (draining) and new workers side by side;
		// the NEWEST worker is the one that read the current config.
		fakeProcWorkers(t, btime, []time.Time{loaded.Add(-2 * time.Hour), loaded})
		_, warn := run(renderDir(loaded.Add(-10 * time.Minute)))
		if len(warn) != 0 {
			t.Fatalf("old draining worker must not trigger the warning: %v", warn)
		}
	})

	t.Run("upgrade rewrote the files but changed nothing -> OK", func(t *testing.T) {
		// The regression this check nearly shipped with: an upgrade renders,
		// every .inc gets a fresh mtime, the config is identical.
		fakeProcWorkers(t, btime, []time.Time{loaded})
		s := renderDir(loaded.Add(-10 * time.Minute))
		now := time.Now()
		for _, n := range []string{"http.inc"} {
			p := filepath.Join(s.Nginx.OutputDir, n)
			if err := os.Chtimes(p, now, now); err != nil {
				t.Fatal(err)
			}
		}
		_, warn := run(s)
		if len(warn) != 0 {
			t.Fatalf("re-rendering identical content must not warn: %v", warn)
		}
	})

	t.Run("no inspectable worker -> silent", func(t *testing.T) {
		fakeProcWorkers(t, btime, nil)
		// pid 1 visible, no worker: nginx is not running, which other checks
		// report (with pid 1 hidden too, the check says it cannot tell).
		if err := os.MkdirAll(filepath.Join(procRoot, "1"), 0o755); err != nil {
			t.Fatal(err)
		}
		ok, warn := run(renderDir(time.Now()))
		if len(ok) != 0 || len(warn) != 0 {
			t.Fatalf("nginx not inspectable must stay silent, got ok=%v warn=%v", ok, warn)
		}
	})
}

// Inside the service the unit hides other processes (ProtectProc=invisible):
// no worker and no pid 1 to be seen.  The check says it cannot tell, with
// the render's time, instead of staying silent -- silence read as fresh to
// the assistant.  With pid 1 visible and no worker, nginx is simply not
// running, which other checks report.
func TestCheckNginxReloadLagHiddenProc(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, nginxconf.SubstantiveRenderMarker)
	if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := settings.Settings{}
	s.Nginx.OutputDir = dir
	run := func() (ok, warn []string) {
		checkNginxReloadLag(s, func(_, m string) { ok = append(ok, m) }, func(_, m string) { warn = append(warn, m) })
		return
	}
	btime := time.Date(2026, 8, 6, 0, 0, 0, 0, time.Local).Unix()
	fakeProcWorkers(t, btime, nil)
	if ok, warn := run(); len(ok) != 0 || len(warn) != 1 || !strings.Contains(warn[0], "hides other processes") || !strings.Contains(warn[0], "unmask doctor") {
		t.Errorf("hidden /proc: want the cannot-tell warning, got ok=%v warn=%v", ok, warn)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, warn := run(); len(ok)+len(warn) != 0 {
		t.Errorf("pid 1 visible, no worker: want silence, got ok=%v warn=%v", ok, warn)
	}
}

// Inside the service, with the daemon's access-log record beside the render:
// the check gives the verdict the log supports instead of "cannot tell".
func TestCheckNginxReloadLagFromTheAccessLog(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := settings.Settings{}
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	cur, written := nginxconf.RenderIDOnDisk(dir)
	run := func() (ok, warn []string) {
		checkNginxReloadLag(s, func(_, m string) { ok = append(ok, m) }, func(_, m string) { warn = append(warn, m) })
		return
	}
	btime := time.Date(2026, 8, 6, 0, 0, 0, 0, time.Local).Unix()
	fakeProcWorkers(t, btime, nil) // hidden /proc: no worker, no pid 1

	w := renderwatch.New(func() string { return dir })
	// nginx logs a configuration from before render ids, after the write.
	w.Saw("", written.Add(2*time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	if ok, warn := run(); len(ok) != 0 || len(warn) != 1 || !strings.Contains(warn[0], "NOT live") || !strings.Contains(warn[0], cur) {
		t.Errorf("stale per the access log: want the older-render warning naming %s, got ok=%v warn=%v", cur, ok, warn)
	}
	// The reload: nginx logs the current id.
	w.Saw(cur, written.Add(3*time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	if ok, warn := run(); len(warn) != 0 || len(ok) != 1 || !strings.Contains(ok[0], cur) {
		t.Errorf("fresh per the access log: want OK naming %s, got ok=%v warn=%v", cur, ok, warn)
	}
}
