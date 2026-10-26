package ban

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// openMirrorTest: a migrated SQLite and a manager with a ban file and a
// one-hour automatic ban.
func openMirrorTest(t *testing.T) (*db.DB, *Manager, string) {
	t.Helper()
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
	return d, New(d, banFile, time.Hour), banFile
}

// The checks answer from memory: the table is read once per write of the
// file, not once per line of the access log.  Rows deleted behind the
// manager's back stay in force until the next load; a load drops them.  And
// the memory matches the way the module matches the file: by the shape each
// row's scope gives it, whatever else the row stores.
func TestChecksAreServedFromMemory(t *testing.T) {
	d, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	const ja4 = "t13d1516h2_8daaf6152771_aaaaaaaaaaaa"
	mgr.Add("203.0.113.1", ja4) // ip_ja4
	if err := mgr.AddManualWithScope(ctx, "203.0.113.2", ja4, ScopeJA4Only, "the fingerprint, from anywhere", "op", "captcha_only", 0); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddManualWithScope(ctx, "203.0.113.3", "t13d_other", ScopeIPOnly, "the address, whatever it presents", "op", "", 0); err != nil {
		t.Fatal(err)
	}
	if n := mgr.MirrorSize(); n != 3 {
		t.Fatalf("mirror holds %d bans, want 3", n)
	}
	for _, c := range []struct {
		ip, ja4    string
		want       bool
		wantAction string
	}{
		{"203.0.113.1", ja4, true, ""},
		{"203.0.113.1", "t13d_other", false, ""},   // an (address, fingerprint) ban: not another fingerprint from the address
		{"203.0.113.9", ja4, true, "captcha_only"}, // ja4_only: the fingerprint from any address
		{"203.0.113.2", "t13d_other", false, ""},   // the ja4_only row's stored address alone bans nothing
		{"203.0.113.3", "t13d_zzz", true, ""},      // ip_only: any fingerprint from the address
		{"203.0.113.3", "", true, ""},
		{"203.0.113.1", "", true, ""}, // no fingerprint: any row naming the address
		{"203.0.113.2", "", true, "captcha_only"},
		{"203.0.113.9", "", false, ""},
	} {
		action, _, got := mgr.IsBannedActionSource(ctx, c.ip, c.ja4)
		if got != c.want || (got && action != c.wantAction) {
			t.Errorf("IsBannedActionSource(%q, %q) = %q %v, want %q %v", c.ip, c.ja4, action, got, c.wantAction, c.want)
		}
	}
	// Behind the manager's back: the table emptied.  The memory answers on.
	if err := d.Gorm.Exec(`DELETE FROM unmask_ban`).Error; err != nil {
		t.Fatal(err)
	}
	if !mgr.IsBanned(ctx, "203.0.113.1", ja4) {
		t.Error("the check went to the table (or the memory is stale) after the rows were deleted behind the manager's back")
	}
	mgr.reloadMirror()
	if mgr.IsBanned(ctx, "203.0.113.1", ja4) || mgr.MirrorSize() != 0 {
		t.Error("a load did not drop the deleted rows")
	}
}

// An ip_ja4 ban on (A, j) does not reach (A, k): the address is banned as
// a whole only by an ip_only row, or by the escalation.
func TestTupleBanDoesNotWidenToTheAddress(t *testing.T) {
	_, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	mgr.Add("203.0.113.1", "t13d_a")
	if _, _, banned := mgr.IsBannedActionSource(ctx, "203.0.113.1", "t13d_b"); banned {
		t.Error("an (address, fingerprint) ban reached another fingerprint from the address")
	}
}

// A row's expiry is judged at the check, not at the load.
func TestMirrorHonoursExpiry(t *testing.T) {
	d, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := d.Gorm.Exec(`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope) VALUES (?, '', 'honeypot', '', ?, ?, '', 'deny', 'ip_only')`,
		"203.0.113.4", now, now+1).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Gorm.Exec(`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope) VALUES (?, '', 'honeypot', '', ?, ?, '', 'deny', 'ip_only')`,
		"203.0.113.5", now-100, now-1).Error; err != nil {
		t.Fatal(err)
	}
	mgr.reloadMirror()
	if mgr.IsBanned(ctx, "203.0.113.5", "") {
		t.Error("an expired row is in force")
	}
	if !mgr.IsBanned(ctx, "203.0.113.4", "") {
		t.Fatal("a row with a second to live is not in force")
	}
	time.Sleep(1100 * time.Millisecond)
	if mgr.IsBanned(ctx, "203.0.113.4", "") {
		t.Error("the row is in force past its expiry, without a load in between")
	}
}

// A ban kept while the database's writes are held is in force from the kept
// list, ahead of the memory, which does not have it.
func TestKeptBansAnswerBeforeTheMirror(t *testing.T) {
	d, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	mgr.Add("203.0.113.6", "t13d_a")
	before := mgr.MirrorSize()
	d.HoldWrites(true)
	mgr.Add("203.0.113.7", "t13d_a")
	if mgr.MirrorSize() != before {
		t.Error("a kept ban went into the memory before its row")
	}
	if action, source, ok := mgr.IsBannedActionSource(ctx, "203.0.113.7", "t13d_a"); !ok || source != SourceHoneypot || action != "" {
		t.Errorf("the kept ban: %q %q %v", action, source, ok)
	}
	d.HoldWrites(false)
	mgr.writeHeld()
	if mgr.MirrorSize() != before+1 || !mgr.IsBanned(ctx, "203.0.113.7", "t13d_a") {
		t.Error("the written ban is not in the memory")
	}
}

// A banned scanner that keeps tripping the trap costs nothing: no row
// written, no file written, nothing announced -- until the refresh interval
// has passed, or the ban would be a different one (another action).
func TestRepeatedTripsAreNotRewritten(t *testing.T) {
	d, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	created := 0
	mgr.OnCreated = func(ip, ja4, source, reason, bannedBy string) { created++ }
	const ip, ja4 = "203.0.113.8", "t13d_a"
	for i := 0; i < 50; i++ {
		mgr.AddWithSourceAction(ctx, ip, ja4, SourceHoneypot, fmt.Sprintf("trap /%d", i), "", "")
	}
	mgr.settle()
	if created != 1 {
		t.Errorf("OnCreated ran %d times for one client, want once", created)
	}
	if n := mgr.flushCount(); n > 2 {
		t.Errorf("the file was written %d times for one client, want at most the first trip's write and one more", n)
	}
	if n := mgr.RepeatedTrips(); n != 49 {
		t.Errorf("RepeatedTrips = %d, want 49", n)
	}
	var reason string
	if err := d.QueryRow(`SELECT reason FROM unmask_ban WHERE ip = ?`, ip).Scan(&reason); err != nil || reason != "trap /0" {
		t.Errorf("the row was rewritten: reason %q (%v), want the first trip's", reason, err)
	}
	// The operator changed the trap's action: the next trip rewrites the row.
	mgr.AddWithSourceAction(ctx, ip, ja4, SourceHoneypot, "trap /x", "", "captcha_only")
	if created != 2 {
		t.Errorf("a trip under a new action did not rewrite the ban (OnCreated %d)", created)
	}
	if action, _, _ := mgr.IsBannedActionSource(ctx, ip, ja4); action != "captcha_only" {
		t.Errorf("the check answers %q after the rewrite, want captcha_only", action)
	}
	// Once the row is older than the refresh interval, a trip refreshes it.
	mgr.mirrorMu.Lock()
	for i := range mgr.mirror.tuple[ip+"|"+ja4] {
		mgr.mirror.tuple[ip+"|"+ja4][i].bannedAt -= 2 * int64(mgr.refreshInterval()/time.Second)
	}
	mgr.mirrorMu.Unlock()
	mgr.AddWithSourceAction(ctx, ip, ja4, SourceHoneypot, "trap /y", "", "captcha_only")
	if created != 3 {
		t.Errorf("a trip past the refresh interval did not refresh the ban (OnCreated %d)", created)
	}
	// An operator's ban is never skipped.
	if err := mgr.AddManualWithScope(ctx, ip, ja4, ScopeIPJA4, "by hand", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if created != 4 {
		t.Errorf("the operator's ban was skipped (OnCreated %d)", created)
	}
}

// A short ban is refreshed at half its lifetime, so a client that keeps
// tripping stays banned; a long one once an hour.
func TestRefreshInterval(t *testing.T) {
	if got := New(nil, "", 0).refreshInterval(); got != time.Hour {
		t.Errorf("permanent bans: %v, want 1h", got)
	}
	if got := New(nil, "", 24*time.Hour).refreshInterval(); got != time.Hour {
		t.Errorf("day-long bans: %v, want 1h", got)
	}
	if got := New(nil, "", 30*time.Minute).refreshInterval(); got != 15*time.Minute {
		t.Errorf("half-hour bans: %v, want 15m", got)
	}
}

// A burst of bans is one write of the file at the end of the window, after
// the first, which is written at once; a lone ban after a quiet spell is
// written at once too.  Every ban is in the checks the moment it is placed.
func TestFlushIsDebounced(t *testing.T) {
	_, mgr, banFile := openMirrorTest(t)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("203.0.113.%d", 100+i)
		if err := mgr.AddManualWithScope(ctx, ip, "", ScopeIPOnly, "burst", "op", "deny", 0); err != nil {
			t.Fatal(err)
		}
		if !mgr.IsBanned(ctx, ip, "") {
			t.Fatalf("%s is not in the checks right after it was placed", ip)
		}
	}
	took := time.Since(t0)
	n := mgr.flushCount()
	// One write per window at most, plus the first: a loaded runner can
	// stretch the loop over several windows, so the bound follows the time.
	if limit := 2 + int(took/flushDebounce); n > limit {
		t.Errorf("the file was written %d times for 30 bans in %v, want at most %d", n, took, limit)
	}
	if n < 1 {
		t.Error("the first ban did not write the file at once")
	}
	mgr.settle()
	buf, _ := os.ReadFile(banFile)
	for i := 0; i < 30; i++ {
		if want := fmt.Sprintf("203.0.113.%d||manual|deny", 100+i); !strings.Contains(string(buf), want) {
			t.Errorf("the file lacks %q after the window", want)
		}
	}
	// A quiet spell, then one ban: written before the call returns.
	time.Sleep(flushDebounce + 50*time.Millisecond)
	before := mgr.flushCount()
	if err := mgr.AddManualWithScope(ctx, "203.0.113.200", "", ScopeIPOnly, "alone", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if mgr.flushCount() != before+1 {
		t.Error("a lone ban after a quiet spell was not written at once")
	}
	buf, _ = os.ReadFile(banFile)
	if !strings.Contains(string(buf), "203.0.113.200||manual|deny") {
		t.Error("the lone ban is not in the file")
	}
}

// Rows written in another spelling of the address -- before the door fixed
// it, or by hand -- are rewritten once at start in the spelling the request
// carries; one whose fixed spelling another row already has goes.  Until
// then the memory and the file carry the fixed spelling anyway.
func TestStartRewritesAddressSpellings(t *testing.T) {
	d, mgr, banFile := openMirrorTest(t)
	ctx := context.Background()
	now := time.Now().Unix()
	ins := func(ip, ja4, scope string) {
		if err := d.Gorm.Exec(`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by, action, scope) VALUES (?, ?, 'manual', '', ?, 0, 'op', 'deny', ?)`,
			ip, ja4, now, scope).Error; err != nil {
			t.Fatal(err)
		}
	}
	ins("2001:DB8::1", "", ScopeIPOnly)
	ins("2001:0db8:0000::2", "t13d_a", ScopeIPJA4)
	ins("2001:DB8::3", "", ScopeIPOnly)
	ins("2001:db8::3", "", ScopeIPOnly) // the fixed spelling, there already
	ins("::FFFF:203.0.113.5", "", ScopeIPOnly)
	mgr.Start()
	defer mgr.Close()
	var ips []string
	rows, err := d.Query(`SELECT ip FROM unmask_ban ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		ips = append(ips, ip)
	}
	rows.Close()
	if got, want := strings.Join(ips, " "), "2001:db8::1 2001:db8::2 2001:db8::3 ::ffff:203.0.113.5"; got != want {
		t.Errorf("rows after start: %q, want %q", got, want)
	}
	for _, c := range []struct{ ip, ja4 string }{
		{"2001:db8::1", ""}, {"2001:DB8::1", ""}, {"2001:db8::2", "t13d_a"}, {"2001:db8::3", ""}, {"::ffff:203.0.113.5", ""},
	} {
		if !mgr.IsBanned(ctx, c.ip, c.ja4) {
			t.Errorf("IsBanned(%q, %q) is false after the rewrite", c.ip, c.ja4)
		}
	}
	buf, _ := os.ReadFile(banFile)
	for _, want := range []string{"2001:db8::1||manual|deny", "2001:db8::2|t13d_a|manual|deny", "2001:db8::3||manual|deny", "::ffff:203.0.113.5||manual|deny"} {
		if !strings.Contains(string(buf), want) {
			t.Errorf("the file lacks %q:\n%s", want, buf)
		}
	}
	if strings.Contains(string(buf), "DB8") || strings.Contains(string(buf), "0db8") {
		t.Errorf("the file carries an unfixed spelling:\n%s", buf)
	}
}

// Whatever spelling arrives at the door -- a ban typed by hand, a check from
// a proxy header -- is the one the file and the memory use.
func TestDoorNormalizesSpellings(t *testing.T) {
	_, mgr, banFile := openMirrorTest(t)
	ctx := context.Background()
	if err := mgr.AddManualWithScope(ctx, "2001:DB8:0:0:0:0:0:9", "", ScopeIPOnly, "typed", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	mgr.Add("2001:0DB8::A", "t13d_a")
	mgr.settle()
	for _, c := range []struct{ ip, ja4 string }{
		{"2001:db8::9", ""}, {"2001:DB8::9", "t13d_x"}, {"2001:db8::a", "t13d_a"}, {"2001:0db8:0000:0000:0000:0000:0000:000a", "t13d_a"},
	} {
		if !mgr.IsBanned(ctx, c.ip, c.ja4) {
			t.Errorf("IsBanned(%q, %q) is false", c.ip, c.ja4)
		}
	}
	buf, _ := os.ReadFile(banFile)
	for _, want := range []string{"2001:db8::9||manual|deny", "2001:db8::a|t13d_a|honeypot|deny"} {
		if !strings.Contains(string(buf), want) {
			t.Errorf("the file lacks %q:\n%s", want, buf)
		}
	}
	// Lifting by the kept-ban key normalises too.
	if mgr.DropHeld("2001:DB8::9", "", ScopeIPOnly) {
		t.Error("DropHeld found a kept ban where the ban is a row of the table")
	}
}

// A lifted or edited row leaves the memory at once.
func TestEditsReachTheMirrorAtOnce(t *testing.T) {
	d, mgr, _ := openMirrorTest(t)
	ctx := context.Background()
	if err := mgr.AddManualWithScope(ctx, "203.0.113.20", "", ScopeIPOnly, "x", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := d.QueryRow(`SELECT id FROM unmask_ban WHERE ip = '203.0.113.20'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := mgr.UpdateManual(ctx, id, "203.0.113.21", "", ScopeIPOnly, "moved", "captcha_only", 0); err != nil {
		t.Fatal(err)
	}
	if mgr.IsBanned(ctx, "203.0.113.20", "") {
		t.Error("the old address of an edited row is still in force")
	}
	if action, _, ok := mgr.IsBannedActionSource(ctx, "203.0.113.21", ""); !ok || action != "captcha_only" {
		t.Errorf("the edited row: %q %v", action, ok)
	}
	if err := mgr.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if mgr.IsBanned(ctx, "203.0.113.21", "") {
		t.Error("a lifted row is still in force")
	}
}
