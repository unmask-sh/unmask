package settings

import (
	"reflect"
	"testing"
)

// TestChallengeResolveUndeclared: an undeclared site returns Default verbatim.
func TestChallengeResolveUndeclared(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			Theme:                 "default",
		},
	}
	got := c.Resolve("blog.example.com")
	if !reflect.DeepEqual(got, c.Default) {
		t.Fatalf("undeclared: want %+v, got %+v", c.Default, got)
	}
}

// TestChallengeResolveDeclared: a declared site returns the entry verbatim.
// Every field reflects the entry's value, even ones equal to Default.
func TestChallengeResolveDeclared(t *testing.T) {
	shop := ChallengeValues{
		PowCookieValidSeconds: 86400 * 7,
		PowDifficulty:         16,
		Theme:                 "terminal",
		ShowCredit:            true,
	}
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			Theme:                 "default",
		},
		Sites: map[string]ChallengeValues{
			"shop.example.com": shop,
		},
	}
	got := c.Resolve("shop.example.com")
	if !reflect.DeepEqual(got, shop) {
		t.Fatalf("declared: want %+v, got %+v", shop, got)
	}
}

// TestChallengeResolveEmptyEntry: an empty entry returns the zero value (=
// no field-level fallback to Default).
func TestChallengeResolveEmptyEntry(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			Theme:                 "default",
		},
		Sites: map[string]ChallengeValues{
			"empty.example.com": {},
		},
	}
	got := c.Resolve("empty.example.com")
	if !reflect.DeepEqual(got, ChallengeValues{}) {
		t.Fatalf("empty entry: want zero, got %+v", got)
	}
	if got.PowDifficulty == c.Default.PowDifficulty {
		t.Fatalf("empty entry leaked Default.PowDifficulty=%d (would be field-level inherit)", c.Default.PowDifficulty)
	}
}

// TestChallengeResolveAfterDelete: dropping a site returns to Default verbatim.
func TestChallengeResolveAfterDelete(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 18, Theme: "default"},
		Sites: map[string]ChallengeValues{
			"shop.example.com": {PowDifficulty: 16, Theme: "terminal"},
		},
	}
	if got := c.Resolve("shop.example.com"); got.Theme != "terminal" {
		t.Fatalf("pre-delete: want Theme=terminal, got %q", got.Theme)
	}
	delete(c.Sites, "shop.example.com")
	got := c.Resolve("shop.example.com")
	if !reflect.DeepEqual(got, c.Default) {
		t.Fatalf("post-delete: want default %+v, got %+v", c.Default, got)
	}
}

// TestChallengeResolveEmptyConfig: zero-value ChallengeConfig returns the
// zero ChallengeValues for every site.
func TestChallengeResolveEmptyConfig(t *testing.T) {
	var c ChallengeConfig
	if got := c.Resolve(""); !reflect.DeepEqual(got, ChallengeValues{}) {
		t.Fatalf("empty config, empty site: want zero, got %+v", got)
	}
	if got := c.Resolve("some.example.com"); !reflect.DeepEqual(got, ChallengeValues{}) {
		t.Fatalf("empty config, real site: want zero, got %+v", got)
	}
}

// TestChallengeResolveMethodsOnValues: helper methods on ChallengeValues
// still behave correctly via Resolve (= the wire is intact).
func TestChallengeResolveMethodsOnValues(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 0}, // out of range -> 18
		Sites: map[string]ChallengeValues{
			"shop.example.com": {PowDifficulty: 20},
		},
	}
	if d := c.Resolve("blog.example.com").ResolvedPowDifficulty(); d != 18 {
		t.Fatalf("default resolved difficulty: want 18, got %d", d)
	}
	if d := c.Resolve("shop.example.com").ResolvedPowDifficulty(); d != 20 {
		t.Fatalf("shop resolved difficulty: want 20, got %d", d)
	}
}
