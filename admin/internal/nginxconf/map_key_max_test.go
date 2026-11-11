package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The longest map key nginx loads, as the configuration in force sizes the
// bucket: what the community-bans writer may put in its files, and what a
// per-site map's host name may be before nginx refuses the configuration.
func TestMapKeyMaxFollowsTheBucket(t *testing.T) {
	for _, c := range []struct {
		name, conf string
		want       int
	}{
		{"http.inc sizes it", "http {\n}\n", 238},
		{"a map before the include keeps the default", "http {\n  map $http_upgrade $x { default 0; }\n}\n", 46},
		{"the host's own size", "http {\n  map_hash_bucket_size 128;\n  map $http_upgrade $x { default 0; }\n}\n", 110},
		{"unreadable: http.inc emits", "", 238},
	} {
		var s settings.Settings
		s.Nginx.ConfPath = filepath.Join(t.TempDir(), "nginx.conf")
		if c.conf != "" {
			if err := os.WriteFile(s.Nginx.ConfPath, []byte(c.conf), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := CommunityBansMapKeyMax(s); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	// 64 holds 46 and not 47 (nginx -t on a 47-byte key: "could not build map_hash").
	if bucketKeyMax(64) != 46 {
		t.Errorf("bucketKeyMax(64) = %d, want 46", bucketKeyMax(64))
	}
}

// A per-site map keyed by a host name longer than the default bucket holds:
// with nothing declared and no map before the include, http.inc sizes the
// bucket even with the community bans off; where it cannot, the render says
// how to fix it.
func TestLongSiteNameSizesTheBucketOrWarns(t *testing.T) {
	long := strings.Repeat("a", 40) + ".example.com" // 52 bytes
	build := func(t *testing.T, conf string) renderData {
		t.Helper()
		dir := t.TempDir()
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(s.Nginx.ConfPath, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		s.Challenge.Sites = map[string]settings.ChallengeValues{long: {PowDifficulty: 12}}
		d, err := buildRenderData(s, dir, "test")
		if err != nil {
			t.Fatalf("buildRenderData: %v", err)
		}
		return d
	}
	if d := build(t, "http {\n}\n"); !d.CommunityBansMapHashBucket || longestHostKey(d) != long {
		t.Errorf("the bucket is not sized for %q (bucket=%v, longest=%q)", long, d.CommunityBansMapHashBucket, longestHostKey(d))
	}
	d := build(t, "http {\n  map $http_upgrade $x { default 0; }\n}\n")
	if d.CommunityBansMapHashBucket {
		t.Fatal("emitted the bucket after the host's map block")
	}
	if !strings.Contains(d.mapHashWarning, long) || !strings.Contains(d.mapHashWarning, "map_hash_bucket_size 256") {
		t.Errorf("no warning naming the site and the fix: %q", d.mapHashWarning)
	}
}
