package logsafe

import "testing"

func TestString(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":            "203.0.113.9",
		"/x\nadmin IP denied: y": `/x\nadmin IP denied: y`,
		"a\r\nb":                 `a\r\nb`,
		"tab\there":              `tab\there`,
		"esc\x1b[31m":            `esc\x1b[31m`,
		"del\x7f":                `del\x7f`,
		"日本語 and a \n newline":   `日本語 and a \n newline`,
	} {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStrings(t *testing.T) {
	got := Strings([]string{"a", "b\nc"})
	if len(got) != 2 || got[0] != "a" || got[1] != `b\nc` {
		t.Fatalf("Strings: %q", got)
	}
	if got := Strings(nil); len(got) != 0 {
		t.Fatalf("Strings(nil): %q", got)
	}
}
