package settings

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadNormalizesMySQLDriverAlias: `driver: mysql` in a hand-written
// config must reach every consumer as the canonical "mariadb" -- the wire
// protocol and Go driver are the same, and internal branches (db.Open, the
// retention estimates, render) all compare against the canonical value, so
// an un-normalized alias would fail at Open and mis-branch everywhere else.
func TestLoadNormalizesMySQLDriverAlias(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("db:\n  driver: MySQL\n  mariadb:\n    host: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(s.DB.Driver) != "mariadb" {
		t.Fatalf("driver = %q, want the canonical mariadb", s.DB.Driver)
	}
	s2, err := LoadFromYAML("db:\n  driver: mysql\n")
	if err != nil {
		t.Fatal(err)
	}
	if string(s2.DB.Driver) != "mariadb" {
		t.Fatalf("LoadFromYAML driver = %q, want mariadb", s2.DB.Driver)
	}
}
