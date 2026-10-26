package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// readTarGz returns the archive's entries by name.
func readTarGz(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Mode&0o077 != 0 {
			t.Errorf("%s is not owner-only: mode %o", hdr.Name, hdr.Mode)
		}
		out[hdr.Name] = body
	}
	return out
}

// The archive holds config.yml as it is on disk and a copy of the database
// that opens and carries every committed row -- the ones still in the
// write-ahead log included, which is what VACUUM INTO gives and a copy of
// the file would not.  The temporary snapshot the copy was taken from is
// gone afterwards, and the daemon's own file is as it was.
func TestBackupArchivesConfigAndDatabase(t *testing.T) {
	config, database := migrateConfig(t, "")
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: database})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event (site, host, ip_address, ja4, phase, payload_json, date_created)
			VALUES ('s','h', X'0a000001', 't13d', 'serve', '{}', CURRENT_TIMESTAMP)`); err != nil {
			t.Fatal(err)
		}
	}
	// The rows are in the write-ahead log, not yet in the file.
	if st, err := os.Stat(database + "-wal"); err != nil || st.Size() == 0 {
		t.Fatalf("the test needs rows in the write-ahead log (stat: %v)", err)
	}

	out := t.TempDir()
	var said []string
	path, err := runBackup(context.Background(), config, out, time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC), func(f string, a ...any) {
		said = append(said, strings.TrimSpace(strings.ReplaceAll(f, "%s", "x")))
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(out, "unmask-backup-20261024-010203.tar.gz"); path != want {
		t.Errorf("archive at %s, want %s", path, want)
	}
	entries := readTarGz(t, path)
	cfg, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(entries["config.yml"]) != string(cfg) {
		t.Errorf("config.yml in the archive differs from the file:\n%s", entries["config.yml"])
	}
	snap, ok := entries["unmask.sqlite"]
	if !ok {
		t.Fatalf("no database in the archive; entries: %v", keysOf(entries))
	}
	if len(entries) != 2 {
		t.Errorf("unexpected entries: %v", keysOf(entries))
	}
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	if err := os.WriteFile(restored, snap, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sql.Open("sqlite", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var check string
	if err := c.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("the copy does not pass integrity_check: %q %v", check, err)
	}
	var n int
	if err := c.QueryRow(`SELECT count(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("the copy holds %d events, want the 3 committed (the write-ahead log was not included)", n)
	}
	// Nothing but the archive is left where it was written.
	left, _ := os.ReadDir(out)
	if len(left) != 1 || left[0].Name() != filepath.Base(path) {
		var names []string
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Errorf("the output directory holds %v, want the archive alone", names)
	}
	if st, err := os.Stat(database); err != nil || st.Size() == 0 {
		t.Errorf("the live database was touched: %v", err)
	}
	if len(said) < 2 {
		t.Errorf("the run reported %d lines, want the config and the database: %v", len(said), said)
	}
}

// A MariaDB install gets config.yml alone, and is told the database is
// mysqldump's to keep.
func TestBackupMariaDBHoldsConfigAlone(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yml")
	body := "db:\n  driver: mariadb\n  mariadb:\n    host: db.example\n    port: 3306\n" +
		"secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var said []string
	path, err := runBackup(context.Background(), config, dir, time.Now(), func(f string, a ...any) { said = append(said, f) })
	if err != nil {
		t.Fatal(err)
	}
	entries := readTarGz(t, path)
	if len(entries) != 1 || string(entries["config.yml"]) != body {
		t.Errorf("entries %v, want config.yml alone with the file's content", keysOf(entries))
	}
	if !strings.Contains(strings.Join(said, "\n"), "mysqldump") {
		t.Errorf("the run must say the database is mysqldump's to back up: %v", said)
	}
}

// The uploaded logos go in under branding/: every file in the branding
// directory, plus a logo the config names elsewhere; a logo_path to a file
// that is gone is skipped, and the same file is never archived twice.
func TestBackupArchivesBrandingLogos(t *testing.T) {
	dir := t.TempDir()
	branding := filepath.Join(dir, "branding")
	if err := os.MkdirAll(branding, 0o755); err != nil {
		t.Fatal(err)
	}
	old := backupBrandingDir
	backupBrandingDir = branding
	t.Cleanup(func() { backupBrandingDir = old })
	for name, body := range map[string]string{"logo.png": "PNG-default", "logo.shop.example.svg": "<svg/>"} {
		if err := os.WriteFile(filepath.Join(branding, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := filepath.Join(dir, "old-logo.jpg")
	if err := os.WriteFile(elsewhere, []byte("JPEG-elsewhere"), 0o640); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yml")
	body := "db:\n  driver: mariadb\n  mariadb:\n    host: db.example\n    port: 3306\n" +
		"secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n" +
		"branding:\n  default:\n    logo_path: " + filepath.Join(branding, "logo.png") + "\n" +
		"  sites:\n    shop.example:\n      logo_path: " + elsewhere + "\n" +
		"    gone.example:\n      logo_path: " + filepath.Join(dir, "missing.png") + "\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var said []string
	path, err := runBackup(context.Background(), config, dir, time.Now(), func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) })
	if err != nil {
		t.Fatal(err)
	}
	entries := readTarGz(t, path)
	for name, want := range map[string]string{
		"branding/logo.png":              "PNG-default",
		"branding/logo.shop.example.svg": "<svg/>",
		"branding/old-logo.jpg":          "JPEG-elsewhere",
	} {
		if string(entries[name]) != want {
			t.Errorf("%s in the archive = %q, want %q", name, entries[name], want)
		}
	}
	if len(entries) != 4 {
		t.Errorf("entries %v, want config.yml and the three logos", keysOf(entries))
	}
	if !strings.Contains(strings.Join(said, "\n"), "branding/logo.png") {
		t.Errorf("the run must name each logo it copied: %v", said)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
