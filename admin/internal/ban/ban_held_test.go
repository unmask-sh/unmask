package ban

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// TestKeptBansAreEnforcedAtOnce: a ban kept while a schema update holds the
// writes is enforced meanwhile -- the ban file (native) is written from the
// table and the kept bans, and the checks (forward-auth) look at both -- where
// it used to wait for the end of the build.  A scanner that trips the
// honeypot again and again is one entry, not thousands.
func TestKeptBansAreEnforcedAtOnce(t *testing.T) {
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
	ctx := context.Background()

	d.HoldWrites(true)
	for i := 0; i < 50; i++ {
		mgr.AddWithSourceAction(ctx, "203.0.113.40", "t13d_y", SourceHoneypot, "trap /wp-login.php", "", "")
	}
	mgr.AddWithSourceAction(ctx, "203.0.113.41", "", SourceHoneypot, "trap /.env", "", "deny")
	mgr.mu.Lock()
	kept := len(mgr.held)
	mgr.mu.Unlock()
	if kept != 2 {
		t.Errorf("%d kept bans for two clients", kept)
	}
	if !mgr.IsBanned(ctx, "203.0.113.40", "t13d_y") || !mgr.IsBanned(ctx, "203.0.113.41", "") {
		t.Error("a kept ban is not enforced by the checks")
	}
	if action, source, ok := mgr.IsBannedActionSource(ctx, "203.0.113.41", ""); !ok || action != "deny" || source != SourceHoneypot {
		t.Errorf("the check's answer for a kept ban = %q %q %v", action, source, ok)
	}
	file, _ := os.ReadFile(banFile)
	for _, want := range []string{"203.0.113.40|t13d_y|honeypot|", "203.0.113.41||honeypot|deny"} {
		if !strings.Contains(string(file), want) {
			t.Errorf("the ban file does not carry the kept ban %q:\n%s", want, file)
		}
	}

	// At shutdown, with the lock free: written.
	mgr.FlushHeld() // still held: nothing
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d written while writes were held", n)
	}
	d.HoldWrites(false)
	mgr.FlushHeld()
	_ = d.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n)
	if n != 2 {
		t.Errorf("%d of 2 kept bans written", n)
	}
}

// TestKeptBansStayInTheFileWhileWritten: the kept bans are written to the
// table one at a time once the hold ends, and an addition's flush can come in
// between.  A kept ban leaves the list only once its row is there: the file
// written in between carries every one of them, where it used to carry only
// those already written -- the rest were unbanned until the next flush.
func TestKeptBansStayInTheFileWhileWritten(t *testing.T) {
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
	ctx := context.Background()

	d.HoldWrites(true)
	mgr.AddWithSourceAction(ctx, "203.0.113.50", "", SourceHoneypot, "trap /wp-login.php", "", "deny")
	mgr.AddWithSourceAction(ctx, "203.0.113.51", "", SourceHoneypot, "trap /.env", "", "deny")
	d.HoldWrites(false)

	var between []byte
	mgr.OnCreated = func(ip, ja4, source, reason, bannedBy string) {
		if between == nil { // after the first row, before the second
			if err := mgr.flush(); err != nil {
				t.Error(err)
			}
			between, _ = os.ReadFile(banFile)
		}
	}
	mgr.writeHeld()
	for _, want := range []string{"203.0.113.50||honeypot|deny", "203.0.113.51||honeypot|deny"} {
		if !strings.Contains(string(between), want) {
			t.Errorf("the file written while the kept bans were being written lacks %q:\n%s", want, between)
		}
	}
	mgr.mu.Lock()
	left := len(mgr.held)
	mgr.mu.Unlock()
	if left != 0 {
		t.Errorf("%d kept ban(s) still listed after they were written", left)
	}
}

// TestKeptBansAreWrittenOnce: the loop's tick and the daemon's shutdown can
// write the kept bans at the same moment.  Each is written, and announced,
// once.
func TestKeptBansAreWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	mgr := New(d, filepath.Join(dir, "ban.list"), time.Hour)
	ctx := context.Background()
	d.HoldWrites(true)
	for i := 0; i < 20; i++ {
		mgr.AddWithSourceAction(ctx, fmt.Sprintf("203.0.113.%d", 100+i), "", SourceHoneypot, "trap /.env", "", "deny")
	}
	d.HoldWrites(false)

	var mu sync.Mutex
	announced := map[string]int{}
	mgr.OnCreated = func(ip, ja4, source, reason, bannedBy string) {
		mu.Lock()
		announced[ip]++
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.writeHeld()
		}()
	}
	wg.Wait()
	for ip, n := range announced {
		if n != 1 {
			t.Errorf("%s announced %d times", ip, n)
		}
	}
	if len(announced) != 20 {
		t.Errorf("%d of 20 kept bans announced", len(announced))
	}
}
