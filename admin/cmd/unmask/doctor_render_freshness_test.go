package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCheckRenderFreshness covers the freshness comparison's four outcomes:
// no live conf to compare, a stamp-only difference (still fresh), a
// substantive drift (stale warning), and an exact match.
func TestCheckRenderFreshness(t *testing.T) {
	body := func(stamp, upstream string) []byte {
		return []byte("#  generated_at: " + stamp + "\n" +
			"#  unmask_version: 0.1.10\n" +
			"upstream unmask_daemon { server 127.0.0.1:9477; }\n" +
			"map $http_user_agent $is_search_bot { default 0; }\n" +
			upstream)
	}

	t.Run("no live conf -> silent", func(t *testing.T) {
		fresh, live := t.TempDir(), t.TempDir()
		_ = os.WriteFile(filepath.Join(fresh, "http.inc"), body("A", ""), 0o644)
		// live has nothing
		c, ok, warn, _ := newCaptures()
		checkRenderFreshness(fresh, live, warn, ok)
		if len(c.ok)+len(c.warn) != 0 {
			t.Errorf("expected no output when nothing to compare, got ok=%v warn=%v", c.ok, c.warn)
		}
	})

	t.Run("stamp-only diff -> fresh (OK)", func(t *testing.T) {
		fresh, live := t.TempDir(), t.TempDir()
		// Same substance, DIFFERENT generated_at/version stamps.
		_ = os.WriteFile(filepath.Join(fresh, "http.inc"), body("2026-07-25T10:00", ""), 0o644)
		_ = os.WriteFile(filepath.Join(live, "http.inc"), []byte("#  generated_at: 2026-07-01T08:00\n#  unmask_version: 0.1.9\nupstream unmask_daemon { server 127.0.0.1:9477; }\nmap $http_user_agent $is_search_bot { default 0; }\n"), 0o644)
		c, ok, warn, _ := newCaptures()
		checkRenderFreshness(fresh, live, warn, ok)
		if len(c.warn) != 0 {
			t.Errorf("stamp-only diff must NOT warn (hourly re-Save churn), got warn=%v", c.warn)
		}
		if len(c.ok) != 1 || !strings.Contains(c.ok[0], "matches") {
			t.Errorf("expected a match OK, got ok=%v", c.ok)
		}
	})

	t.Run("substantive drift -> stale WARN", func(t *testing.T) {
		fresh, live := t.TempDir(), t.TempDir()
		_ = os.WriteFile(filepath.Join(fresh, "http.inc"), body("A", "# new hand-edit reflected\n"), 0o644)
		_ = os.WriteFile(filepath.Join(live, "http.inc"), body("B", ""), 0o644) // missing the new line
		c, _, warn, _ := newCaptures()
		checkRenderFreshness(fresh, live, warn, warn)
		if len(c.warn) != 1 {
			t.Fatalf("expected 1 stale warning, got %v", c.warn)
		}
		for _, want := range []string{"http.inc", "render-nginx", "out of date"} {
			if !strings.Contains(c.warn[0], want) {
				t.Errorf("warning missing %q: %s", want, c.warn[0])
			}
		}
	})

	t.Run("exact match -> OK", func(t *testing.T) {
		fresh, live := t.TempDir(), t.TempDir()
		for _, d := range []string{fresh, live} {
			_ = os.WriteFile(filepath.Join(d, "http.inc"), body("A", ""), 0o644)
			_ = os.WriteFile(filepath.Join(d, "server.inc"), []byte("location / { proxy_pass http://unmask_daemon; }\n"), 0o644)
		}
		c, ok, warn, _ := newCaptures()
		checkRenderFreshness(fresh, live, warn, ok)
		if len(c.warn) != 0 || len(c.ok) != 1 {
			t.Errorf("exact match: want 1 OK 0 warn, got ok=%v warn=%v", c.ok, c.warn)
		}
	})

	t.Run("empty output_dir -> no-op", func(t *testing.T) {
		c, ok, warn, _ := newCaptures()
		checkRenderFreshness(t.TempDir(), "", warn, ok)
		if len(c.ok)+len(c.warn) != 0 {
			t.Errorf("empty output_dir must be silent, got ok=%v warn=%v", c.ok, c.warn)
		}
	})
}

// Doctor renders into a temp dir and compares that with the live render.  The
// render id (rv=) hashes the files, which name the directory they were written
// to, so the two ids differ even when nothing else does: an install whose
// render is current must read fresh, and a real change must be reported at
// its own line, not at the id.
func TestRenderFreshnessAcrossDirs(t *testing.T) {
	live := t.TempDir()
	conf := filepath.Join(live, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := settings.Settings{}
	s.Nginx.OutputDir = live
	s.Nginx.ConfPath = conf
	if err := nginxconf.Render(s, live, "test"); err != nil {
		t.Fatal(err)
	}
	check := func(s settings.Settings) (ok, warn []string) {
		fresh := t.TempDir()
		if err := nginxconf.Render(s, fresh, "test"); err != nil {
			t.Fatal(err)
		}
		if a, _ := nginxconf.RenderIDOnDisk(fresh); a == "" {
			t.Fatal("the dry-run carries no render id")
		}
		checkRenderFreshness(fresh, live,
			func(_, m string) { warn = append(warn, m) },
			func(_, m string) { ok = append(ok, m) })
		return
	}
	if ok, warn := check(s); len(warn) != 0 || len(ok) != 1 {
		t.Errorf("same configuration, another directory: want fresh, got ok=%v warn=%v", ok, warn)
	}
	s.Challenge.Default.PowDifficulty = 20
	_, warn := check(s)
	if len(warn) != 1 {
		t.Fatalf("PoW difficulty changed: want 1 warning, got %v", warn)
	}
	if !strings.Contains(warn[0], "unmask_bv_pow_difficulty") || strings.Contains(warn[0], "log_format") {
		t.Errorf("the warning should point at the difficulty, not the render id: %s", warn[0])
	}
}

func TestStripRenderStamps(t *testing.T) {
	in := []byte("#  generated_at: 2026-07-25\n#  unmask_version: 0.1.10\nupstream x {}\n# generated_at: alt\ncontent\n")
	got := stripRenderStamps(in)
	if strings.Contains(got, "generated_at") || strings.Contains(got, "unmask_version") {
		t.Errorf("stamps not stripped: %q", got)
	}
	for _, want := range []string{"upstream x {}", "content"} {
		if !strings.Contains(got, want) {
			t.Errorf("substance line dropped: %q missing from %q", want, got)
		}
	}
}
