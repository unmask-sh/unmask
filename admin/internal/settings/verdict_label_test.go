package settings

import "testing"

func TestValidVerdictLabel(t *testing.T) {
	for name, want := range map[string]bool{
		"bot_curl":              true,
		"hunt_t13d1516h28daaf6": true,
		"社内ツール":                 true,  // a name that worked before keeps working
		"hunt_t13d1516h2$":      false, // nginx: invalid variable name
		"x$host":                false, // would read $host
		`a"b`:                   false,
		`a\b`:                   false,
		"a\nb":                  false,
		"":                      false,
	} {
		if got := ValidVerdictLabel(name); got != want {
			t.Errorf("ValidVerdictLabel(%q) = %v, want %v", name, got, want)
		}
	}
}
