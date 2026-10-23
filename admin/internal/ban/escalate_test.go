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

// Three automatic (ip, ja4) bans on one address inside a day widen to the
// address itself; two do not, and a manual ban does not count toward it.
func TestAutoBansEscalateToTheAddress(t *testing.T) {
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
	ctx := context.Background()
	const ip = "203.0.113.77"
	ja4 := func(i int) string { return "t13d1516h2_8daaf6152771_" + strings.Repeat(string(rune('a'+i)), 12) }

	mgr.AddAuto(ctx, ip, ja4(0), ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	mgr.AddAuto(ctx, ip, ja4(1), ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	if err := mgr.AddManualWithScope(ctx, ip, ja4(5), ScopeIPJA4, "by hand", "tester", "deny", 0); err != nil {
		t.Fatalf("manual add: %v", err)
	}
	if _, _, b := mgr.IsBannedActionSource(ctx, ip, "t13d1516h2_8daaf6152771_zzzzzzzzzzzz"); b {
		t.Fatal("the address was widened after two automatic bans (the manual one must not count)")
	}
	mgr.AddAuto(ctx, ip, ja4(2), ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	act, src, b := mgr.IsBannedActionSource(ctx, ip, "t13d1516h2_8daaf6152771_zzzzzzzzzzzz")
	if !b || src != SourceRateLimitAbuse || act != "captcha_only" {
		t.Fatalf("after three fingerprints: banned=%v source=%q action=%q, want an ip_only rate_limit_abuse captcha_only ban", b, src, act)
	}
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), ip+"||"+SourceRateLimitAbuse+"|captcha_only") {
		t.Errorf("the ban file carries no ip-only line for %s:\n%s", ip, buf)
	}
	// A fourth fingerprint widens nothing further (one ip_only row).
	mgr.AddAuto(ctx, ip, ja4(3), ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	n := 0
	for _, e := range mgr.Snapshot() {
		if e.IP == ip && e.Scope == ScopeIPOnly {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ip_only rows for %s: %d, want 1", ip, n)
	}
	// Another address with its own fingerprints is untouched.
	if _, _, b := mgr.IsBannedActionSource(ctx, "203.0.113.78", "t13d1516h2_8daaf6152771_zzzzzzzzzzzz"); b {
		t.Error("the escalation reached another address")
	}
}
