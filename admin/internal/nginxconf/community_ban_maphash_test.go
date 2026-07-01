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

	t.Run("host_map_block_skip_both_and_warn", func(t *testing.T) {
		// Alpine 3.23's stock nginx.conf opens `map $http_upgrade $connection_upgrade {}`
		// before the unmask include.  nginx forbids map_hash_bucket_size after a
		// map block, so emitting ours in http.inc would be a fatal duplicate --
		// Render must skip BOTH directives and warn.
		d := build(t, "http {\n  map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n}\n", settings.SubscribeFetchApply)
		if d.CommunityBansMapHashBucket || d.CommunityBansMapHashMax {
			t.Errorf("host opens a map block: must skip both, got bucket=%v max=%v", d.CommunityBansMapHashBucket, d.CommunityBansMapHashMax)
		}
		if d.mapHashWarning == "" {
			t.Error("host map block + no map_hash directive: expected a warning")
		}
		if !strings.Contains(d.mapHashWarning, "map") {
			t.Errorf("warning should mention the map block: %s", d.mapHashWarning)
		}
	})

	t.Run("host_map_block_but_adequate_bucket_no_warn", func(t *testing.T) {
		// Operator set map_hash_bucket_size BEFORE the map block (the correct
		// placement): we skip (host declares it) and there is no problem to warn about.
		d := build(t, "http {\n  map_hash_bucket_size 256;\n  map $http_upgrade $x { default 0; }\n}\n", settings.SubscribeFetchApply)
		if d.CommunityBansMapHashBucket {
			t.Error("host declares bucket 256: must not emit")
		}
		if d.mapHashWarning != "" {
			t.Errorf("operator sized it correctly before the map block: want no warning, got: %s", d.mapHashWarning)
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

// TestForwardAuthGateLoadsAfterMapHash guards the 2026-06-28 native regression:
// the forward-auth LB-trust gate (forward-auth-lbtrust.conf) carries geo/map
// blocks, and nginx PINS map_hash_bucket_size the moment it parses the first
// map/geo block -- so a later map_hash_bucket_size (http.inc emits one for the
// community-bans maps) is a fatal "directive is duplicate".  The web-nginx
// package wires the gate as a conf.d symlink (zz-unmask-fa-lbtrust.conf) that
// sorts AFTER http.inc (00-unmask.conf) so http.inc's sizing is parsed first.
// This asserts the rendered output is compatible with that order: across
// [http.inc ++ forward-auth-lbtrust.conf] (= the conf.d load order), the first
// map_hash_bucket_size must appear before the first geo/map block.  The symlink
// NAMING that produces this order is verified by the distro-check install matrix;
// this guards the render output in `go test` (fast, every change).
func TestForwardAuthGateLoadsAfterMapHash(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.CommunityBans.SubscribeMode = settings.SubscribeFetchApply // -> http.inc emits map_hash
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	httpInc, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	faGate, err := os.ReadFile(filepath.Join(dir, "forward-auth-lbtrust.conf"))
	if err != nil {
		t.Fatalf("forward-auth-lbtrust.conf not rendered: %v", err)
	}
	// conf.d alphabetical load order: 00-unmask.conf (http.inc) then
	// zz-unmask-fa-lbtrust.conf (the gate).
	combined := string(httpInc) + "\n# ---- zz-unmask-fa-lbtrust.conf ----\n" + string(faGate)

	mapHashLine, firstMapGeoLine := -1, -1
	for i, raw := range strings.Split(combined, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // ignore blanks + comments
		}
		if firstMapGeoLine < 0 && (strings.HasPrefix(line, "map ") || strings.HasPrefix(line, "geo ")) {
			firstMapGeoLine = i
		}
		if mapHashLine < 0 && strings.HasPrefix(line, "map_hash_bucket_size") {
			mapHashLine = i
		}
	}
	if mapHashLine < 0 {
		t.Fatal("community-bans active: expected map_hash_bucket_size in the combined conf.d stream")
	}
	if firstMapGeoLine < 0 {
		t.Fatal("expected at least one map/geo block in the combined stream")
	}
	if mapHashLine > firstMapGeoLine {
		t.Errorf("map_hash_bucket_size (line %d) appears AFTER the first map/geo block (line %d) in conf.d load order "+
			"-- nginx will reject it as a duplicate (the 2026-06-28 native regression). "+
			"The gate must load after http.inc (zz- symlink name); check render order / symlink naming.",
			mapHashLine, firstMapGeoLine)
	}
}
