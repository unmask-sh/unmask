// Tests for the community-bans map_hash sizing that Render emits into http.inc
// (instead of editing nginx.conf).  The ipja4 key reaches ~76 chars with IPv6,
// overflowing nginx's default map_hash_bucket_size (64); the directive is a
// single-occurrence http{} one, so Render must skip it when the host nginx.conf
// already declares it -- and warn when that host value is too small.
package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestCommunityBansMapHashSizing(t *testing.T) {
	const missing = "\x00missing\x00"
	build := func(t *testing.T, confBody, mode string) renderData {
		t.Helper()
		dir := t.TempDir()
		conf := filepath.Join(dir, "nginx.conf")
		if confBody != missing {
			if err := os.WriteFile(conf, []byte(confBody), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = conf
		s.CommunityBans.SubscribeMode = mode
		d, err := buildRenderData(s, dir, "test")
		if err != nil {
			t.Fatalf("buildRenderData: %v", err)
		}
		return d
	}

	t.Run("host_has_neither_emit_both", func(t *testing.T) {
		d := build(t, "http {\n}\n", settings.SubscribeFetchApply)
		if !d.CommunityBansMapHashBucket || !d.CommunityBansMapHashMax {
			t.Errorf("want both emitted, got bucket=%v max=%v", d.CommunityBansMapHashBucket, d.CommunityBansMapHashMax)
		}
		if d.mapHashWarning != "" {
			t.Errorf("unexpected warning: %s", d.mapHashWarning)
		}
	})

	t.Run("host_adequate_bucket_skip_no_warn", func(t *testing.T) {
		d := build(t, "map_hash_bucket_size 256;\nhttp {\n}\n", settings.SubscribeFetchApply)
		if d.CommunityBansMapHashBucket {
			t.Error("must not emit bucket when host already declares 256 (would duplicate)")
		}
		if d.mapHashWarning != "" {
			t.Errorf("256 is adequate, want no warning, got: %s", d.mapHashWarning)
		}
	})

	t.Run("host_low_bucket_skip_but_warn", func(t *testing.T) {
		d := build(t, "map_hash_bucket_size 64;\nhttp {\n}\n", settings.SubscribeFetchApply)
		if d.CommunityBansMapHashBucket {
			t.Error("must not emit bucket when host already declares one (would duplicate)")
		}
		if d.mapHashWarning == "" {
			t.Error("host bucket 64 < 256: expected a warning")
		}
		if !strings.Contains(d.mapHashWarning, "64") {
			t.Errorf("warning should name the offending value: %s", d.mapHashWarning)
		}
	})

	t.Run("host_set_only_max_emit_only_bucket", func(t *testing.T) {
		d := build(t, "map_hash_max_size 8192;\nhttp {\n}\n", settings.SubscribeFetchApply)
		if !d.CommunityBansMapHashBucket {
			t.Error("host lacks bucket -> must emit bucket")
		}
		if d.CommunityBansMapHashMax {
			t.Error("host has max -> must not emit max (would duplicate)")
		}
	})

	t.Run("unreadable_conf_emit_both_and_note", func(t *testing.T) {
		d := build(t, missing, settings.SubscribeFetchApply)
		if !d.CommunityBansMapHashBucket || !d.CommunityBansMapHashMax {
			t.Error("unreadable conf: emit both (safe default)")
		}
		if d.mapHashWarning == "" {
			t.Error("unreadable conf: expected a note")
		}
	})

	t.Run("off_mode_no_maphash", func(t *testing.T) {
		d := build(t, "http {\n}\n", settings.SubscribeOff)
		if d.CommunityBansMapHashBucket || d.CommunityBansMapHashMax {
			t.Error("off mode: no community-bans maps -> no map_hash")
		}
		if d.mapHashWarning != "" {
			t.Errorf("off mode: unexpected warning: %s", d.mapHashWarning)
		}
	})
}

// TestRenderEmitsMapHashIntoHttpInc verifies the directives actually land in the
// rendered http.inc (end-to-end through Render), before the community-bans maps.
func TestRenderEmitsMapHashIntoHttpInc(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	bucketAt := strings.Index(got, "map_hash_bucket_size 256;")
	if bucketAt < 0 {
		t.Fatal("http.inc missing map_hash_bucket_size 256;")
	}
	if !strings.Contains(got, "map_hash_max_size 4096;") {
		t.Error("http.inc missing map_hash_max_size 4096;")
	}
	// must precede the community-bans map include (nginx builds the hash at parse).
	if mapAt := strings.Index(got, "community-bans-ipja4.map"); mapAt >= 0 && bucketAt > mapAt {
		t.Error("map_hash_bucket_size must appear before the community-bans map block")
	}
}
