package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func egressManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	banFile := filepath.Join(dir, "ban.list")
	mgr := New(d, banFile, 0)
	mgr.SetEgress(func(ip string) (string, bool) {
		if strings.HasPrefix(ip, "198.51.100.") {
			return "cloudfront", true
		}
		return "", false
	})
	return mgr, banFile
}

// An automatic ban -- the honeypot's, the pass budget's -- on a CDN's
// origin-facing address is not placed; an operator's own on the same
// address is, and holds.
func TestEgressGetsNoAutomaticBan(t *testing.T) {
	mgr, banFile := egressManager(t)
	ctx := context.Background()
	const cdnIP, ja4 = "198.51.100.7", "t13d230800_bfd000000000_000000000000"
	mgr.Add(cdnIP, ja4)
	mgr.AddAuto(ctx, cdnIP, ja4, ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	if _, _, b := mgr.IsBannedActionSource(ctx, cdnIP, ja4); b {
		t.Fatal("an automatic ban landed on the CDN address")
	}
	if n := len(mgr.Snapshot()); n != 0 {
		t.Fatalf("%d rows after automatic bans on a CDN address, want 0", n)
	}
	// Another address is banned as before.
	mgr.Add("203.0.113.9", ja4)
	if _, _, b := mgr.IsBannedActionSource(ctx, "203.0.113.9", ja4); !b {
		t.Fatal("a plain address was not banned")
	}
	// The operator's own ban on the CDN address holds, and is in the file.
	if err := mgr.AddManual(ctx, cdnIP, ja4, "by hand", "alice", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if _, src, b := mgr.IsBannedActionSource(ctx, cdnIP, ja4); !b || src != "manual" {
		t.Fatalf("the operator's ban on the CDN address: banned=%v source=%q", b, src)
	}
	mgr.settle()
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), cdnIP+"|"+ja4+"|manual|deny") {
		t.Errorf("the operator's ban is not in the file:\n%s", buf)
	}
}

// Automatic bans from before the list knew the address -- rows already in
// the table -- are left out of the file and of the check, and counted, as
// soon as the lookup says the address is a CDN's.
func TestEgressRowsLeaveTheFile(t *testing.T) {
	mgr, banFile := egressManager(t)
	ctx := context.Background()
	const cdnIP, ja4 = "198.51.100.8", "t13d230900_bfd000000000_000000000000"
	// Placed while the address was nobody's: swap the lookup out, ban, swap it back.
	mgr.SetEgress(nil)
	mgr.Add(cdnIP, ja4)
	mgr.Add(cdnIP, "t13d230800_bfd000000000_000000000000")
	mgr.settle()
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), cdnIP+"|"+ja4) {
		t.Fatalf("the ban is not in the file before the list knows the address:\n%s", buf)
	}
	mgr.SetEgress(func(ip string) (string, bool) { return "cloudfront", strings.HasPrefix(ip, "198.51.100.") })
	if err := mgr.flush(); err != nil {
		t.Fatal(err)
	}
	buf, _ = os.ReadFile(banFile)
	if strings.Contains(string(buf), cdnIP) {
		t.Errorf("the CDN address is still in the file:\n%s", buf)
	}
	if n := mgr.EgressSkipped(); n != 2 {
		t.Errorf("EgressSkipped = %d, want 2", n)
	}
	if _, _, b := mgr.IsBannedActionSource(ctx, cdnIP, ja4); b {
		t.Error("the daemon's check still holds the ban on the CDN address")
	}
	if n := len(mgr.Snapshot()); n != 2 {
		t.Errorf("the rows must stay in the table for the page: %d", n)
	}
	// The escalation to the address as a whole does not happen either.
	mgr.Add(cdnIP, "t13d230700_bfd000000000_000000000000")
	for _, e := range mgr.Snapshot() {
		if e.Scope == ScopeIPOnly {
			t.Error("the CDN address was banned as a whole")
		}
	}
}
