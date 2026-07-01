package nginxconf

import "testing"

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.1", "v0.2", true},
		{"v0.2", "v0.1", false},
		{"v0.1", "v0.1", false},
		{"v0.9", "v0.10", true}, // int-parse, not lexicographic
		{"v0.1", "v0.1.5", false},
		{"0.1.0", "v0.2", true},
		{"v1.0", "v0.9", false},
	}
	for _, c := range cases {
		if got := VersionLess(c.a, c.b); got != c.want {
			t.Errorf("VersionLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionParseable(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"v0.1", true},
		{"0.1.0", true},
		{"v1", true},
		{"", false},
		{"v6f94983", false},     // git hash stamped by a dev build
		{"vdev-6f94983", false}, // dev-prefixed build stamp
		{"v0.x", false},
	}
	for _, c := range cases {
		if got := VersionParseable(c.v); got != c.want {
			t.Errorf("VersionParseable(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestPresetIsNew(t *testing.T) {
	cases := []struct {
		seen, added string
		want        bool
	}{
		{"v0.1", "v0.2", true},  // release upgrade -> badge the new preset
		{"v0.2", "v0.1", false}, // already seen
		{"v0.1", "v0.1", false}, // same release
		// A git-hash SeenVersion (= dev / source build saved the settings
		// page) must not read as v0.0: that flagged every preset as new and
		// dropped enabled presets from the rendered conf.
		{"v6f94983", "v0.1", false},
		{"v6f94983", "v99.0", false},
		{"", "v0.1", false}, // unknown seen -> hide nothing
	}
	for _, c := range cases {
		if got := PresetIsNew(c.seen, c.added); got != c.want {
			t.Errorf("PresetIsNew(%q, %q) = %v, want %v", c.seen, c.added, got, c.want)
		}
	}
}
