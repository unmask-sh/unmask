package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A honeypot hit arrives on the access log's receive loop while a schema
// update holds the write lock.  The ban must not make that loop wait out the
// busy timeout at every hit (the socket behind it drops what it cannot hold),
// and must not be lost because its write failed: it is kept, and written when
// the lock is free.
func TestAutomaticBanWaitsForHeldWrites(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	banFile := filepath.Join(dir, "ban.list")
	mgr := New(d, banFile, time.Hour)
	created := 0
	mgr.OnCreated = func(ip, ja4, source, reason, bannedBy string) { created++ }
	rows := func() int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	d.HoldWrites(true)
	t0 := time.Now()
	mgr.AddWithSourceAction(context.Background(), "203.0.113.30", "t13d_x", SourceHoneypot, "trap /wp-login.php", "", "deny")
	mgr.AddWithSourceAction(context.Background(), "203.0.113.31", "", SourceHoneypot, "trap /.env", "", "")
	if took := time.Since(t0); took > 200*time.Millisecond {
		t.Errorf("two bans took %v while writes were held; they must not wait for the lock", took)
	}
	if n := rows(); n != 0 {
		t.Fatalf("%d ban(s) written while writes were held", n)
	}
	if created != 0 {
		t.Error("the ban was announced before it was written")
	}
	before := time.Now().Unix()

	d.HoldWrites(false)
	mgr.writeHeld()
	if mgr.shouldFlush() {
		if err := mgr.flush(); err != nil {
			t.Fatal(err)
		}
	}
	if n := rows(); n != 2 {
		t.Fatalf("%d of 2 kept bans were written", n)
	}
	if created != 2 {
		t.Errorf("OnCreated ran %d times, want once per ban", created)
	}
	// The ban dates from the hit, not from when it could be written: its
	// expiry is counted from the offence.
	var bannedAt int64
	if err := d.QueryRow(`SELECT banned_at FROM unmask_ban WHERE ip = '203.0.113.30'`).Scan(&bannedAt); err != nil {
		t.Fatal(err)
	}
	if bannedAt > before {
		t.Errorf("banned_at = %d, after the hold ended (%d)", bannedAt, before)
	}
	file, _ := os.ReadFile(banFile)
	for _, want := range []string{"203.0.113.30|t13d_x|honeypot|deny", "203.0.113.31|"} {
		if !strings.Contains(string(file), want) {
			t.Errorf("the ban file does not carry %q:\n%s", want, file)
		}
	}
	// Written once: a second pass finds nothing kept.
	mgr.writeHeld()
	if n := rows(); n != 2 || created != 2 {
		t.Errorf("a second pass wrote again: rows=%d created=%d", n, created)
	}
}
