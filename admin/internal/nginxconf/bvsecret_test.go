package nginxconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBVSecretDirective(t *testing.T) {
	cases := []struct{ in, want string }{
		{`unmask_bv_secret                "abc123";`, "abc123"},
		{`unmask_bv_secret "x";`, "x"},
		{"map $http_x ...\nunmask_bv_secret \"mid\";\nmore", "mid"},
		{"no directive here", ""},
		{`unmask_bv_secret "unterminated`, ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractBVSecretDirective(c.in); got != c.want {
			t.Errorf("extractBVSecretDirective(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBVSecretDesynced: only a concrete mismatch counts; empty secrets or a
// missing render are "not desynced" (nothing to compare).
func TestBVSecretDesynced(t *testing.T) {
	dir := t.TempDir()
	write := func(secret string) {
		if err := os.WriteFile(filepath.Join(dir, "http.inc"), []byte(`unmask_bv_secret "`+secret+`";`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("same")
	if BVSecretDesynced(dir, "same") {
		t.Error("matching secrets reported as desynced")
	}
	if !BVSecretDesynced(dir, "different") {
		t.Error("mismatched secrets not reported as desynced")
	}
	if BVSecretDesynced(dir, "") {
		t.Error("empty config secret should be a no-op, not a desync")
	}
	if BVSecretDesynced(t.TempDir(), "any") {
		t.Error("absent http.inc should be a no-op, not a desync")
	}
}
