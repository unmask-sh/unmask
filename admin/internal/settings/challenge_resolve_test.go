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
			ChallengeHTMLPath:     "/srv/default.html",
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
		ChallengeHTMLPath:     "/srv/shop.html",
		ObserveOnly:           BoolPtr(true),
	}
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			ChallengeHTMLPath:     "/srv/default.html",
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

// TestChallengeResolveEmptyEntryInherits: an entry that sets nothing now reads
// exactly like Default.  It used to return the zero value instead -- which is
// how a site that had been given one setting quietly lost every other one, and
// why the settings page had to seed each new record with a full snapshot of
// Default to compensate.
func TestChallengeResolveEmptyEntryInherits(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			ChallengeHTMLPath:     "/srv/default.html",
		},
		Sites: map[string]ChallengeValues{
			"empty.example.com": {},
		},
	}
	if got := c.Resolve("empty.example.com"); !reflect.DeepEqual(got, c.Default) {
		t.Fatalf("empty entry: want Default %+v, got %+v", c.Default, got)
	}
}

// TestChallengeResolveMergesPerField: what the site sets wins; what it leaves
// alone keeps following Default, so raising a global knob reaches sites that
// override a different one.
func TestChallengeResolveMergesPerField(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{
			PowCookieValidSeconds: 86400 * 3,
			PowDifficulty:         18,
			DebugRateLimitPer5Min: 20,
			PublicTestPages:       BoolPtr(true),
		},
		Sites: map[string]ChallengeValues{
			"shop.example.com": {PowDifficulty: 22},
		},
	}
	got := c.Resolve("shop.example.com")
	if got.PowDifficulty != 22 {
		t.Errorf("the field the site set = %d, want 22", got.PowDifficulty)
	}
	if got.PowCookieValidSeconds != 86400*3 || got.DebugRateLimitPer5Min != 20 {
		t.Errorf("untouched fields did not inherit: %+v", got)
	}
	// Raising a global knob now reaches the site.
	c.Default.DebugRateLimitPer5Min = 50
	if got := c.Resolve("shop.example.com"); got.DebugRateLimitPer5Min != 50 {
		t.Errorf("a Default change did not reach an overriding site: %d", got.DebugRateLimitPer5Min)
	}

	// An explicit false must not read as "unset" and inherit true back.
	c.Sites["shop.example.com"] = ChallengeValues{PublicTestPages: BoolPtr(false)}
	if c.Resolve("shop.example.com").IsPublicTestPages() {
		t.Error("an explicitly disabled flag inherited Default's true")
	}
}

// TestChallengeResolveAfterDelete: dropping a site returns to Default verbatim.
func TestChallengeResolveAfterDelete(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 18, ChallengeHTMLPath: "/srv/default.html"},
		Sites: map[string]ChallengeValues{
			"shop.example.com": {PowDifficulty: 16, ChallengeHTMLPath: "/srv/shop.html"},
		},
	}
	if got := c.Resolve("shop.example.com"); got.ChallengeHTMLPath != "/srv/shop.html" {
		t.Fatalf("pre-delete: want the site's own html path, got %q", got.ChallengeHTMLPath)
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
