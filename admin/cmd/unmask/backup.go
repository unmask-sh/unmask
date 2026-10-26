package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cmdBackup: `unmask backup` -- one archive of what an install cannot get
// back any other way: config.yml, the uploaded logos and, on SQLite, the
// database.
//
// The database copy is taken with VACUUM INTO: one read transaction writes
// a consistent snapshot while the daemon keeps running, the pages still in
// the write-ahead log included -- which a copy of unmask.sqlite made by hand
// lacks, so it opens with its last minutes missing or not at all.  The
// logos uploaded on the Page design tab (settings.DefaultBrandingLogoDir,
// named by the config's logo_path entries) go in under branding/.  Nothing
// else under /var/lib/unmask needs keeping: the nginx snippets come back
// from `unmask render-nginx`, the GeoIP and IP range files from their update
// commands.  A MariaDB install backs its database up with mysqldump, and
// the archive then holds config.yml and the logos alone.
//
// Taken before a package upgrade, the archive is what a downgrade restores.
// The schema only moves forward (internal/db/migrator.go), so the older
// version needs the database from before the upgrade, not the upgraded one.
func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	out := fs.String("out", "", "directory the archive is written to (default: the database's directory on SQLite, else the current one)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), backupUsage)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	say := func(f string, a ...any) { fmt.Printf("backup: "+f+"\n", a...) }
	path, err := runBackup(context.Background(), *configPath, *out, time.Now(), say)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	say("wrote %s", path)
	return nil
}

const backupUsage = `usage: unmask backup [-config PATH] [-out DIR]

Writes DIR/unmask-backup-<yyyymmdd-hhmmss, UTC>.tar.gz holding config.yml,
the logos uploaded on the Page design tab (branding/, from
/var/lib/unmask/branding) and, on SQLite, a consistent copy of the database,
taken with VACUUM INTO while the daemon keeps running (what is still in the
write-ahead log is in the copy).  On MariaDB the archive holds config.yml
and the logos alone: back the database up with mysqldump.  Take one before
a package upgrade -- the schema only moves forward, so going back to the
older version needs the database from before it.

Restore:
  1. stop the daemon           systemctl stop unmask   (rc-service unmask stop)
  2. unpack the archive        mkdir /tmp/unmask-restore
                               tar -xzf unmask-backup-....tar.gz -C /tmp/unmask-restore
  3. put the files back        config.yml to /etc/unmask/config.yml; the database
                               file to db.sqlite_path from that config, after
                               removing the -wal and -shm files next to it;
                               the branding/ files to /var/lib/unmask/branding/;
                               chown all of them to the daemon's user (unmask)
  4. start the daemon          systemctl start unmask  (rc-service unmask start)
To return to an older version, install that version between steps 3 and 4.

`

// runBackup writes the archive and returns its path.  now names the file;
// say reports what went in, and what did not.
func runBackup(ctx context.Context, configPath, outDir string, now time.Time, say func(string, ...any)) (string, error) {
	s, err := loadSettings(configPath)
	if err != nil {
		return "", err
	}
	resolved := settings.ResolvePath(configPath)
	if resolved == "" {
		return "", errors.New("no config.yml found (pass -config PATH)")
	}
	sqlite := s.DB.Driver == "" || s.DB.Driver == string(db.DriverSQLite)
	if outDir == "" {
		// The database's directory is the one place known to have room for
		// a copy of the database (see db.OpenMaintenance), and the daemon's
		// user -- which this command runs as -- can write there.
		if sqlite && s.DB.SQLitePath != "" {
			outDir = filepath.Dir(s.DB.SQLitePath)
		} else {
			outDir = "."
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	stamp := now.UTC().Format("20060102-150405")
	path := filepath.Join(outDir, "unmask-backup-"+stamp+".tar.gz")

	// Written under a temporary name and renamed when complete, so a run
	// that stops halfway leaves no archive that looks whole.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	done := false
	defer func() {
		if !done {
			f.Close()
			os.Remove(tmp)
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	n, err := addFileToTar(tw, resolved, "config.yml", now)
	if err != nil {
		return "", fmt.Errorf("config.yml: %w", err)
	}
	say("config.yml  %s  (%s)", humanBytesCLI(n), resolved)

	logos := brandingLogoFiles(s)
	if len(logos) == 0 {
		say("branding: no uploaded logo; nothing to copy")
	}
	for _, p := range logos {
		name := "branding/" + filepath.Base(p)
		n, err := addFileToTar(tw, p, name, now)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		say("%s  %s  (%s)", name, humanBytesCLI(n), p)
	}

	switch {
	case !sqlite:
		say("database: %s is not in the archive; back it up with mysqldump", s.DB.Driver)
	case noSQLiteFile(s.DB):
		say("database: %s does not exist yet; nothing to copy", s.DB.SQLitePath)
	default:
		// The snapshot goes next to the archive, not next to the database:
		// SQLite refuses to write INTO an existing file, and a leftover from
		// an earlier run would otherwise make every later run fail.
		snap := filepath.Join(outDir, ".unmask-backup-"+stamp+".sqlite")
		if err := sqliteSnapshot(ctx, s.DB, snap); err != nil {
			return "", fmt.Errorf("database snapshot: %w", err)
		}
		defer os.Remove(snap)
		name := filepath.Base(s.DB.SQLitePath)
		n, err := addFileToTar(tw, snap, name, now)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		say("%s  %s  (VACUUM INTO snapshot of %s)", name, humanBytesCLI(n), s.DB.SQLitePath)
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	done = true
	return path, nil
}

// backupBrandingDir: where the uploaded logos are; a var for the test.
var backupBrandingDir = settings.DefaultBrandingLogoDir

// brandingLogoFiles: the logo files to archive -- every regular file in the
// branding directory, and any logo_path in the config that lives elsewhere
// (a logo from before the directory existed), each once, in a fixed order.
// A path that does not exist is skipped: a logo_path left behind by a
// removed file is not a reason to fail the backup.
func brandingLogoFiles(s settings.Settings) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	if ents, err := os.ReadDir(backupBrandingDir); err == nil {
		for _, e := range ents {
			add(filepath.Join(backupBrandingDir, e.Name()))
		}
	}
	add(s.Branding.Default.LogoPath)
	sites := make([]string, 0, len(s.Branding.Sites))
	for site := range s.Branding.Sites {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	for _, site := range sites {
		add(s.Branding.Sites[site].LogoPath)
	}
	return out
}

// sqliteSnapshot writes a consistent copy of the database to dst with
// VACUUM INTO: one read transaction, the committed pages of the write-ahead
// log included, the daemon's own writes undisturbed.  dst must not exist.
func sqliteSnapshot(ctx context.Context, cfg settings.DB, dst string) error {
	// A maintenance connection: a single one, with SQLite's temporary
	// storage on disk, as VACUUM's is the size of the database.
	conn, err := db.OpenMaintenance(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	// The target is an expression, so it binds like any value.
	_, err = conn.ExecContext(ctx, "VACUUM INTO ?", dst)
	return err
}

// addFileToTar copies the file at src into tw as a regular entry called
// name, owner-only (the config holds the secrets, the database the
// visitors), and returns its size.
func addFileToTar(tw *tar.Writer, src, name string, modTime time.Time) (int64, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o600,
		Size:     st.Size(),
		ModTime:  modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, err
	}
	// Exactly the size in the header: the archive is corrupt otherwise, and
	// a file that grew meanwhile (the config saved from the UI is written
	// whole and renamed, so it cannot) would be caught here, not on restore.
	if _, err := io.CopyN(tw, f, st.Size()); err != nil {
		return 0, err
	}
	return st.Size(), nil
}
