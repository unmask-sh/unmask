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
// bucket even with the community bans off; where it cannot, the name is
// keyed as a regular expression, which nginx keeps outside the hash.  It
// was written as a plain key with a warning that nginx would refuse the
// configuration, and nginx did: "could not build map_hash", at its next
// reload or start, naming no file.
func TestLongSiteNameSizesTheBucketOrIsKeyedAsARegex(t *testing.T) {
	long := strings.Repeat("a", 40) + ".example.com" // 52 bytes
	short := "shop.example.com"
	build := func(t *testing.T, conf string) (renderData, string) {
		t.Helper()
		dir := t.TempDir()
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(s.Nginx.ConfPath, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		s.Challenge.Sites = map[string]settings.ChallengeValues{long: {PowDifficulty: 12}, short: {PowDifficulty: 14}}
		s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "^/login", Site: long}}
		d, err := buildRenderData(s, dir, "test")
		if err != nil {
			t.Fatalf("buildRenderData: %v", err)
		}
		if err := Render(s, dir, "test"); err != nil {
			t.Fatalf("Render: %v", err)
		}
		inc, err := os.ReadFile(filepath.Join(dir, "http.inc"))
		if err != nil {
			t.Fatal(err)
		}
		return d, string(inc)
	}
	plain, regex := `"`+long+`" 12;`, `"~*^`+strings.ReplaceAll(long, ".", `\\.`)+`$" 12;`

	// http.inc sizes the bucket: the name is a plain key.
	d, inc := build(t, "http {\n}\n")
	if !d.CommunityBansMapHashBucket || longestHostKey(d) != long {
		t.Errorf("the bucket is not sized for %q (bucket=%v, longest=%q)", long, d.CommunityBansMapHashBucket, longestHostKey(d))
	}
	if !strings.Contains(inc, plain) {
		t.Errorf("with the bucket sized, http.inc lacks the plain key %s", plain)
	}

	// A map of the host's ahead of the include: the bucket stays nginx's
	// default, and the long name is an expression in every per-site map.
	d, inc = build(t, "http {\n  map $http_upgrade $x { default 0; }\n}\n")
	if d.CommunityBansMapHashBucket {
		t.Fatal("emitted the bucket after the host's map block")
	}
	if !strings.Contains(inc, regex) || strings.Contains(inc, `"`+long+`"`) {
		t.Errorf("after the host's map block, the long name is not keyed as %s (or is still a plain key)", regex)
	}
	if !strings.Contains(inc, `"`+short+`" 14;`) {
		t.Errorf("the name that fits the bucket is not a plain key")
	}
	if got := longestPlainHostKey(d); len(got) > bucketKeyMax(64) {
		t.Errorf("a plain key of %d bytes is left for a bucket that holds %d: %q", len(got), bucketKeyMax(64), got)
	}
	if strings.Contains(d.mapHashWarning, "refuse") {
		t.Errorf("the render still says nginx will refuse the configuration: %q", d.mapHashWarning)
	}

	// The host's own size decides the same way.
	d, inc = build(t, "http {\n  map_hash_bucket_size 128;\n  map $http_upgrade $x { default 0; }\n}\n")
	if d.CommunityBansMapHashBucket || !strings.Contains(inc, plain) {
		t.Errorf("under the host's 128-byte bucket the name of %d bytes is not a plain key", len(long))
	}
}

// longestPlainHostKey: the longest key of a per-site map that nginx puts in
// its hash (an expression is kept outside it).
func longestPlainHostKey(d renderData) string {
	longest := ""
	for _, r := range d.PowDifficultyHosts {
		if !strings.HasPrefix(r.Host, "~") && len(r.Host) > len(longest) {
			longest = r.Host
		}
	}
	for _, r := range d.ProtectedPathsPerHost {
		if !strings.HasPrefix(r.Host, "~") && len(r.Host) > len(longest) {
			longest = r.Host
		}
	}
	return longest
}

// TestNginxKeysALongHostNameOutsideTheHash asks a real nginx what a per-site
// map answers for a host name too long for the bucket in force, where a map
// of the host's own configuration comes ahead of unmask's include and the
// bucket cannot be sized: the site's own value, as for a name that fits.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxKeysALongHostNameOutsideTheHash(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	const long = "very-long-subdomain-name.marketing.example-company.co.jp" // 56 bytes; the default bucket holds 46
	ask, _ := startNginxWith(t, bin, mod,
		"challenge:\n  default:\n    pow_difficulty: 16\n  sites:\n    \""+long+"\":\n      pow_difficulty: 12\n    \"shop.example.com\":\n      pow_difficulty: 14\n",
		"$unmask_pow_difficulty",
		"    map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n")
	for host, want := range map[string]string{
		long:                    "12",
		strings.ToUpper(long):   "12", // nginx lowers the Host it matches by
		"x" + long:              "16", // anchored at both ends
		long + ".example":       "16",
		"shop.example.com":      "14",
		"elsewhere.example.com": "16",
	} {
		if got := ask(false, map[string]string{"Host": host}); got != want {
			t.Errorf("Host %s: the site's PoW difficulty reads %q, want %q", host, got, want)
		}
	}
}
