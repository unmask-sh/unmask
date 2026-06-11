package settings

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRawBVSecretPresent: the raw probe reports presence of a non-empty
// secret.bv_secret without Load()'s random fill-in, so doctor can tell a real
// configured key from a fabricated one.
func TestRawBVSecretPresent(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.yml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{"present", "secret:\n  bv_secret: abc123xyz\n", true},
		{"empty value", "secret:\n  bv_secret: \"\"\n", false},
		{"whitespace only", "secret:\n  bv_secret: \"   \"\n", false},
		{"missing secret block", "server:\n  port: 9477\n", false},
		{"empty file", "", false},
	}
	for _, c := range cases {
		if got := RawBVSecretPresent(write(c.yaml)); got != c.want {
			t.Errorf("%s: RawBVSecretPresent = %v, want %v", c.name, got, c.want)
		}
	}
	if RawBVSecretPresent(filepath.Join(dir, "does-not-exist.yml")) {
		t.Error("missing file should be reported as not present")
	}
}
