package settings

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The resolver takes PowDifficultyMin..PowDifficultyMax and answers the
// built-in default for everything else, not set included.
func TestResolvedPowDifficultyBounds(t *testing.T) {
	for _, tc := range []struct{ set, want int }{
		{0, PowDifficultyDefault},
		{-1, PowDifficultyDefault},
		{PowDifficultyMin - 1, PowDifficultyDefault},
		{PowDifficultyMin, PowDifficultyMin},
		{20, 20},
		{PowDifficultyMax, PowDifficultyMax},
		{PowDifficultyMax + 1, PowDifficultyDefault},
		{64, PowDifficultyDefault},
	} {
		if got := (ChallengeValues{PowDifficulty: tc.set}).ResolvedPowDifficulty(); got != tc.want {
			t.Errorf("pow_difficulty %d resolves to %d, want %d", tc.set, got, tc.want)
		}
	}
}

// A pow_difficulty outside the range is not applied, and
// PowDifficultyOutOfRange is what tells the operator: the default's record
// first, then the sites' by name.  Not set (0), in range, and a site record
// that is switched off are left out.
func TestPowDifficultyOutOfRange(t *testing.T) {
	c := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 30},
		Sites: map[string]ChallengeValues{
			"b.example":     {PowDifficulty: 7},
			"a.example":     {PowDifficulty: 25},
			"neg.example":   {PowDifficulty: -1},
			"max.example":   {PowDifficulty: PowDifficultyMax},
			"min.example":   {PowDifficulty: PowDifficultyMin},
			"unset.example": {},
			"off.example":   {PowDifficulty: 40, Disabled: true},
		},
	}
	want := []PowDifficultyIssue{
		{Key: "challenge.default.pow_difficulty", Value: 30},
		{Key: "challenge.sites.a.example.pow_difficulty", Value: 25},
		{Key: "challenge.sites.b.example.pow_difficulty", Value: 7},
		{Key: "challenge.sites.neg.example.pow_difficulty", Value: -1},
	}
	got := c.PowDifficultyOutOfRange()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("out of range = %+v\nwant %+v", got, want)
	}

	// What the list says is what runs: every record it names resolves to the
	// built-in default, and so does a record that takes the default's number.
	for _, site := range []string{"a.example", "b.example", "neg.example", "unset.example", "off.example", "nowhere.example"} {
		if d := c.Resolve(site).ResolvedPowDifficulty(); d != PowDifficultyDefault {
			t.Errorf("%s runs at %d, want the built-in %d", site, d, PowDifficultyDefault)
		}
	}
	if d := c.Resolve("max.example").ResolvedPowDifficulty(); d != PowDifficultyMax {
		t.Errorf("a site in range keeps its number: %d, want %d", d, PowDifficultyMax)
	}

	// A site's own number outside the range does not fall back to the default
	// record's number: it runs at the built-in one, which is what the message
	// says.
	mixed := ChallengeConfig{
		Default: ChallengeValues{PowDifficulty: 20},
		Sites:   map[string]ChallengeValues{"shop.example": {PowDifficulty: 4}},
	}
	if got := mixed.PowDifficultyOutOfRange(); !reflect.DeepEqual(got, []PowDifficultyIssue{{Key: "challenge.sites.shop.example.pow_difficulty", Value: 4}}) {
		t.Errorf("a default in range with one site out of range lists the site alone: %+v", got)
	}
	if d := mixed.Resolve("shop.example").ResolvedPowDifficulty(); d != PowDifficultyDefault {
		t.Errorf("shop.example runs at %d, want the built-in %d and not the default record's 20", d, PowDifficultyDefault)
	}
	if d := mixed.Resolve("other.example").ResolvedPowDifficulty(); d != 20 {
		t.Errorf("a site with no record of its own takes the default record's number: %d, want 20", d)
	}

	msg := got[0].String()
	for _, w := range []string{"challenge.default.pow_difficulty is 30", "outside 8-24", "18 bits"} {
		if !strings.Contains(msg, w) {
			t.Errorf("the message must carry %q, got: %s", w, msg)
		}
	}

	for name, quiet := range map[string]ChallengeConfig{
		"nothing set": {},
		"in range": {
			Default: ChallengeValues{PowDifficulty: 20},
			Sites:   map[string]ChallengeValues{"a.example": {PowDifficulty: 12}},
		},
	} {
		if got := quiet.PowDifficultyOutOfRange(); len(got) != 0 {
			t.Errorf("%s: %+v, want nothing", name, got)
		}
	}
}

// Load says it once per record when it reads the file, and loads the file all
// the same with the number as written: it is not an error, it is a number
// that does nothing, and the operator is the one to change it.
func TestLoadWarnsPowDifficultyOutOfRange(t *testing.T) {
	load := func(body string) (Settings, string) {
		t.Helper()
		cfg := filepath.Join(t.TempDir(), "config.yml")
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		s, err := Load(cfg)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return s, buf.String()
	}
	const secrets = "secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n  admin_secret: fedcba9876543210fedcba9876543210\n"

	s, out := load(secrets + "challenge:\n  default:\n    pow_difficulty: 30\n  sites:\n    shop.example:\n      pow_difficulty: 4\n")
	for _, want := range []string{
		"challenge.default.pow_difficulty is 30",
		"challenge.sites.shop.example.pow_difficulty is 4",
		"outside 8-24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the load log must carry %q, got:\n%s", want, out)
		}
	}
	if s.Challenge.Default.PowDifficulty != 30 {
		t.Errorf("Load keeps the number as written (%d, want 30): the warning is the whole of the change", s.Challenge.Default.PowDifficulty)
	}
	if d := s.Challenge.Default.ResolvedPowDifficulty(); d != PowDifficultyDefault {
		t.Errorf("the default record runs at %d, want the built-in %d", d, PowDifficultyDefault)
	}

	if _, out := load(secrets + "challenge:\n  default:\n    pow_difficulty: 20\n"); strings.Contains(out, "pow_difficulty") {
		t.Errorf("a number in range loads in silence, got:\n%s", out)
	}
	if _, out := load(secrets); strings.Contains(out, "pow_difficulty") {
		t.Errorf("no pow_difficulty at all loads in silence, got:\n%s", out)
	}
}
