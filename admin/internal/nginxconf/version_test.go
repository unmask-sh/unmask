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
		{"v0.9", "v0.10", true},  // int-parse, not lexicographic
		{"v0.1", "v0.1.5", true}, // patch counts: releases step by 0.0.1
		{"v0.1.6", "v0.1.7", true},
		{"v0.1.7", "v0.1.7", false},
		{"v0.1.7", "v0.1.6", false},
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
		{"v0.1.7", true},
		{"v1", true},
		{"", false},
		{"v6f94983", false},     // git hash stamped by a dev build (no separator)
		{"vdev-6f94983", false}, // dev-prefixed build stamp
		{"v0.x", false},
		{"v0.1.x", false}, // a present PATCH must be numeric
		// SemVer pre-release / build suffixes are stripped, so a dev / RC build's
		// "MAJOR.MINOR.PATCH-<suffix>" orders by its release number (its
		// SeenVersion must gate presets like the release it is a candidate for).
		{"v0.1.7-rc1", true},
		{"v0.1.7-dev-3a819a7", true},
		{"0.1.7+build.5", true},
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
		{"v0.1", "v0.2", true},      // release upgrade -> badge the new preset
		{"v0.2", "v0.1", false},     // already seen
		{"v0.1", "v0.1", false},     // same release
		{"v0.1.6", "v0.1.7", true},  // patch-step release also badges
		{"v0.1.7", "v0.1.7", false}, // saved on the release that added it
		// A git-hash SeenVersion (= dev / source build saved the settings
		// page) must not read as v0.0: that flagged every preset as new and
		// dropped enabled presets from the rendered conf.
		{"v6f94983", "v0.1", false},
		{"v6f94983", "v99.0", false},
		{"", "v0.1", false}, // unknown seen -> hide nothing
		// A dev / RC build's SeenVersion orders by its release number: saving on
		// "0.1.7-dev-<hash>" reviews the 0.1.7 presets (not new), but a later
		// 0.1.8 preset still badges as new (the suffix does not poison the gate).
		{"v0.1.7-dev-3a819a7", "v0.1.7", false},
		{"v0.1.7-dev-3a819a7", "v0.1.8", true},
	}
	for _, c := range cases {
		if got := PresetIsNew(c.seen, c.added); got != c.want {
			t.Errorf("PresetIsNew(%q, %q) = %v, want %v", c.seen, c.added, got, c.want)
		}
	}
}
