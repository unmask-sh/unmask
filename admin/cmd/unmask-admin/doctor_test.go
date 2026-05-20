package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// captureChecks: simple helper-set collector so the table tests below can
// observe what doctor's helpers emit without printing to stdout.
type checks struct {
	ok, warn, err []string
}

func newCaptures() (*checks, func(t, m string), func(t, m string), func(t, m string)) {
	c := &checks{}
	add := func(slice *[]string) func(t, m string) {
		return func(t, m string) {
			*slice = append(*slice, t+" | "+m)
		}
	}
	return c, add(&c.ok), add(&c.warn), add(&c.err)
}

// TestCheckMMDBPath covers the three significant outcomes:
//   1. file missing  -> WARN with install-ipgeo hint
//   2. file present + not an mmdb -> ERR
//   3. empty path -> no-op (caller filters)
func TestCheckMMDBPath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		expect string // "ok" / "warn" / "err" / "none"
		match  string // substring required in the emitted line
	}{
		{"empty path skipped", "", "none", ""},
		{"missing file WARN", "/nonexistent/path/missing.mmdb", "warn", "install-ipgeo"},
		{"non-mmdb file ERR", "/etc/passwd", "err", "not a valid mmdb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cap, addOK, addWarn, addErr := newCaptures()
			checkMMDBPath("test", c.path, addOK, addWarn, addErr)
			switch c.expect {
			case "ok":
				if len(cap.ok) != 1 {
					t.Fatalf("expected 1 OK, got ok=%v warn=%v err=%v", cap.ok, cap.warn, cap.err)
				}
				if !strings.Contains(cap.ok[0], c.match) {
					t.Errorf("OK line %q does not contain %q", cap.ok[0], c.match)
				}
			case "warn":
				if len(cap.warn) != 1 {
					t.Fatalf("expected 1 WARN, got ok=%v warn=%v err=%v", cap.ok, cap.warn, cap.err)
				}
				if !strings.Contains(cap.warn[0], c.match) {
					t.Errorf("WARN line %q does not contain %q", cap.warn[0], c.match)
				}
			case "err":
				if len(cap.err) != 1 {
					t.Fatalf("expected 1 ERR, got ok=%v warn=%v err=%v", cap.ok, cap.warn, cap.err)
				}
				if !strings.Contains(cap.err[0], c.match) {
					t.Errorf("ERR line %q does not contain %q", cap.err[0], c.match)
				}
			case "none":
				if len(cap.ok)+len(cap.warn)+len(cap.err) != 0 {
					t.Fatalf("expected no output, got ok=%v warn=%v err=%v", cap.ok, cap.warn, cap.err)
				}
			}
		})
	}
}

// TestCheckGeoRules covers:
//   1. empty rules list -> no-op
//   2. all valid country codes -> OK with count
//   3. mixed valid + unknown -> WARN with the unknown ones listed
func TestCheckGeoRules(t *testing.T) {
	mk := func(rules ...settings.GeoRule) settings.Settings {
		return settings.Settings{Nginx: settings.Nginx{Geo: settings.GeoConfig{Rules: rules}}}
	}

	t.Run("empty list silent", func(t *testing.T) {
		cap, addOK, addWarn, _ := newCaptures()
		checkGeoRules(mk(), addOK, addWarn)
		if len(cap.ok)+len(cap.warn) != 0 {
			t.Errorf("expected silent, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("all valid codes -> OK", func(t *testing.T) {
		cap, addOK, addWarn, _ := newCaptures()
		checkGeoRules(mk(
			settings.GeoRule{Country: "JP"},
			settings.GeoRule{Country: "US"},
			settings.GeoRule{Country: "DE"},
		), addOK, addWarn)
		if len(cap.warn) != 0 {
			t.Errorf("expected no WARN, got %v", cap.warn)
		}
		if len(cap.ok) != 1 || !strings.Contains(cap.ok[0], "3 rule(s)") {
			t.Errorf("expected 1 OK with 3 rules, got %v", cap.ok)
		}
	})

	t.Run("typo'd code -> WARN", func(t *testing.T) {
		cap, addOK, addWarn, _ := newCaptures()
		checkGeoRules(mk(
			settings.GeoRule{Country: "JP"},
			settings.GeoRule{Country: "JA"}, // typo for JP
			settings.GeoRule{Country: "ZZ"}, // not assigned
		), addOK, addWarn)
		if len(cap.ok) != 0 {
			t.Errorf("expected no OK, got %v", cap.ok)
		}
		if len(cap.warn) != 1 {
			t.Fatalf("expected 1 WARN, got %v", cap.warn)
		}
		if !strings.Contains(cap.warn[0], "JA") || !strings.Contains(cap.warn[0], "ZZ") {
			t.Errorf("WARN should list both bad codes, got %q", cap.warn[0])
		}
	})
}
