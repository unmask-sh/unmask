package ban

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestScopeIPJA4WithBothFilled: dropdown scope=ip_ja4 keeps the strict
// tuple shape in the ban file even when both IP and JA4 are present.
// Mirrors the BAN modal's "情報として最大限保存、 動作は scope で選ぶ"
// principle: same row contents can flip between scopes.
func TestScopeIPJA4WithBothFilled(t *testing.T) {
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
	const ip = "203.0.113.5"
	const ja4 = "t13d1715h2_abcdefabcdef_0123456789ab"
	if err := mgr.AddManualWithScope(context.Background(), ip, ja4, "ip_ja4", "tuple", "tester", "deny", 0); err != nil {
		t.Fatalf("ip_ja4 scope add: %v", err)
	}
	buf, _ := os.ReadFile(banFile)
	want := ip + "|" + ja4 + "|manual|deny"
	if !strings.Contains(string(buf), want) {
		t.Errorf("ban file missing strict tuple line %q\n---file---\n%s", want, string(buf))
	}
}

// TestScopeJA4OnlyWithIPStored: scope=ja4_only writes "|<ja4>" to the
// file even when an IP is also stored in the DB (= the operator wanted
// to remember the original visitor IP as context).  Verifies the
// "情報保存 + 動作は scope" promise.
func TestScopeJA4OnlyWithIPStored(t *testing.T) {
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
	const ip = "203.0.113.7"
	const ja4 = "t13d1715h2_residential_bot_signature"
	if err := mgr.AddManualWithScope(context.Background(), ip, ja4, "ja4_only", "residential bot", "tester", "captcha_only", 0); err != nil {
		t.Fatalf("ja4_only scope add: %v", err)
	}
	buf, _ := os.ReadFile(banFile)
	want := "|" + ja4 + "|manual|captcha_only"
	if !strings.Contains(string(buf), want) {
		t.Errorf("ban file lacks ja4_only line %q\n---file---\n%s", want, string(buf))
	}
	if strings.Contains(string(buf), ip+"|"+ja4) {
		t.Errorf("ban file unexpectedly contains the strict tuple line — scope=ja4_only should drop IP from the key.\n---file---\n%s", string(buf))
	}
}

// TestScopeIPOnly: scope=ip_only writes "<ip>|" so the C plugin's third
// bsearch pass catches any JA4 from that IP.
func TestScopeIPOnly(t *testing.T) {
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
	if err := mgr.AddManualWithScope(context.Background(), "203.0.113.9", "", "ip_only", "scraper host", "tester", "", 0); err != nil {
		t.Fatalf("ip_only scope add: %v", err)
	}
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), "203.0.113.9||manual|captcha_only") &&
		!strings.Contains(string(buf), "203.0.113.9||manual|deny") {
		t.Errorf("ban file lacks ip-only line\n---file---\n%s", string(buf))
	}
}

// TestAddManualJA4Only: AddManual with empty IP + non-empty JA4 succeeds and
// the flushed ban file carries the entry as "|<ja4>|manual|<action>".
// JA4-only entries let one row ban every visitor with that fingerprint; the
// C plugin's two-pass lookup matches them via key "|<ja4>".
func TestAddManualJA4Only(t *testing.T) {
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

	const ja4 = "t13d1715h2_5b57614c22b0_3d5424432f57"
	if err := mgr.AddManual(ctx, "", ja4, "hunt JA4 ranking", "tester", "deny", 0); err != nil {
		t.Fatalf("AddManual(ip=empty, ja4=%q): %v", ja4, err)
	}

	buf, err := os.ReadFile(banFile)
	if err != nil {
		t.Fatalf("read ban file: %v", err)
	}
	want := "|" + ja4 + "|manual|deny"
	if !strings.Contains(string(buf), want) {
		t.Errorf("ban file does not contain %q\n---file---\n%s", want, string(buf))
	}
}

// TestAddManualBothEmpty: empty IP + empty JA4 -> error.  Sanity guard
// against accidental no-op rows.
func TestAddManualBothEmpty(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := New(d, "", 0)
	err = mgr.AddManual(context.Background(), "", "", "reason", "tester", "", 0)
	if err == nil {
		t.Fatalf("expected error on empty (ip, ja4); got nil")
	}
}

// TestAddManualIPOnly: existing path -- IP without JA4 still works (JA4 column
// is empty in the ban file row).  Guards against the relaxation accidentally
// breaking the pre-existing IP-only flow.
func TestAddManualIPOnly(t *testing.T) {
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
	if err := mgr.AddManual(context.Background(), "1.2.3.4", "", "scan", "tester", "", 0); err != nil {
		t.Fatalf("AddManual(ip=1.2.3.4, ja4=empty): %v", err)
	}
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), "1.2.3.4||manual|deny") {
		t.Errorf("ban file lacks ip-only row\n---file---\n%s", string(buf))
	}
}

// TestScopeCoexistsSameIPJA4: DB-3 — a honeypot ip_ja4 ban and a manual
// ja4_only ban on the SAME (ip, ja4) are distinct rows now, not an overwrite.
// Before scope joined the UNIQUE key, the second ban silently rewrote the
// first, which could widen a single-device ban into a JA4-wide ban.
func TestScopeCoexistsSameIPJA4(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := New(d, filepath.Join(dir, "ban.list"), 0)
	ctx := context.Background()
	const ip = "203.0.113.7"
	const ja4 = "t13d1715h2_abcdefabcdef_0123456789ab"

	// 1. honeypot auto-ban (ip_ja4) on (ip, ja4).
	mgr.AddWithSource(ctx, ip, ja4, SourceHoneypot, "trap", "")
	// 2. manual ban (ja4_only) on the SAME (ip, ja4).
	if err := mgr.AddManualWithScope(ctx, ip, ja4, ScopeJA4Only, "manual", "tester", "deny", 0); err != nil {
		t.Fatalf("manual ja4_only add: %v", err)
	}
	// Both rows must coexist -- 2 rows for the same (ip, ja4).
	var n int64
	d.Gorm.Model(&db.Ban{}).Where("ip = ? AND ja4 = ?", ip, ja4).Count(&n)
	if n != 2 {
		t.Fatalf("expected 2 coexisting rows (ip_ja4 + ja4_only), got %d", n)
	}
	// The honeypot row must still be honeypot/ip_ja4 (not overwritten).
	var hpCount int64
	d.Gorm.Model(&db.Ban{}).Where("ip = ? AND ja4 = ? AND source = ? AND scope = ?", ip, ja4, SourceHoneypot, ScopeIPJA4).Count(&hpCount)
	if hpCount != 1 {
		t.Fatalf("honeypot ip_ja4 row was overwritten (expected 1, got %d)", hpCount)
	}
	// Re-adding the same (ip, ja4, ip_ja4) updates in place (no 3rd row).
	mgr.AddWithSource(ctx, ip, ja4, SourceHoneypot, "trap-again", "")
	d.Gorm.Model(&db.Ban{}).Where("ip = ? AND ja4 = ?", ip, ja4).Count(&n)
	if n != 2 {
		t.Fatalf("same (ip,ja4,scope) re-add should update, not insert; got %d rows", n)
	}
}

// TestMigrateBanUniqueScopeFromOld: DB-3 — an old DB with UNIQUE(ip,ja4) is
// migrated to UNIQUE(ip,ja4,scope) with rows preserved, and re-running Migrate
// is a no-op.  Simulates a pre-DB-3 install by creating the old table shape
// before Migrate runs.
func TestMigrateBanUniqueScopeFromOld(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	ctx := context.Background()
	// Old schema: UNIQUE(ip, ja4) (no scope in the key), with scope column.
	if _, err := d.ExecContext(ctx, `CREATE TABLE unmask_ban (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip VARCHAR(64) NOT NULL, ja4 VARCHAR(40) NOT NULL,
		source VARCHAR(32) NOT NULL, reason VARCHAR(255),
		banned_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
		banned_by VARCHAR(64), action VARCHAR(32) NOT NULL DEFAULT '',
		scope VARCHAR(16) NOT NULL DEFAULT 'ip_ja4',
		UNIQUE (ip, ja4) )`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	// Also need unmask_event so markBaselineIfNeeded treats this as an existing DB.
	if _, err := d.ExecContext(ctx, `INSERT INTO unmask_ban (ip, ja4, source, banned_at, scope) VALUES ('1.2.3.4','jx','honeypot',1,'ip_ja4')`); err != nil {
		t.Fatalf("seed old row: %v", err)
	}

	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate (old->new): %v", err)
	}
	// Old row preserved.
	var n int64
	d.Gorm.Model(&db.Ban{}).Count(&n)
	if n != 1 {
		t.Fatalf("expected 1 preserved row after migration, got %d", n)
	}
	// New key allows a 2nd scope on the same (ip, ja4).
	mgr := New(d, "", 0)
	if err := mgr.AddManualWithScope(ctx, "1.2.3.4", "jx", ScopeJA4Only, "m", "t", "deny", 0); err != nil {
		t.Fatalf("scope-aware insert after migration failed: %v", err)
	}
	d.Gorm.Model(&db.Ban{}).Where("ip = ? AND ja4 = ?", "1.2.3.4", "jx").Count(&n)
	if n != 2 {
		t.Fatalf("expected 2 rows (ip_ja4 + ja4_only) after migration, got %d", n)
	}
	// Re-running Migrate is a no-op (idempotent).
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate (re-run): %v", err)
	}
	d.Gorm.Model(&db.Ban{}).Count(&n)
	if n != 2 {
		t.Fatalf("re-run Migrate changed row count to %d (want 2)", n)
	}
}

// TestWhitelistBypassesHoneypotBan: the bypass allowlist is preset + CIDR-aware
// (the admin injects a closure over IPBypassMatcher) and hot-reloadable.  The
// old literal-IP map could match neither a crawler CIDR nor a freshly-toggled
// bypass without a restart -- the M-3 / DB-4 bug that let a Googlebot range
// landing on a honeypot URI get auto-banned (CLAUDE.md #4).
func TestWhitelistBypassesHoneypotBan(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := New(d, filepath.Join(dir, "ban.list"), 0)
	ctx := context.Background()
	const ja4 = "t13d1715h2_abcdefabcdef_0123456789ab"

	// CIDR-aware closure — the shape the admin injects from IPBypassMatcher; a
	// literal-IP map could not match a range like this.
	mgr.SetWhitelist(func(ip string) bool {
		_, nw, err := net.ParseCIDR("66.249.64.0/19") // Googlebot-style range
		return err == nil && nw.Contains(net.ParseIP(ip))
	})

	// An IP inside the bypass CIDR must NOT be honeypot-banned.
	mgr.AddWithSource(ctx, "66.249.70.5", ja4, SourceHoneypot, "", "")
	if mgr.IsBanned(ctx, "66.249.70.5", ja4) {
		t.Fatal("a whitelisted preset-CIDR IP must not be honeypot-banned")
	}
	// An IP outside the range IS banned.
	mgr.AddWithSource(ctx, "1.2.3.4", ja4, SourceHoneypot, "", "")
	if !mgr.IsBanned(ctx, "1.2.3.4", ja4) {
		t.Fatal("a non-whitelisted IP should be honeypot-banned")
	}
	// Manual BAN of a whitelisted IP is refused with a clear error.
	if err := mgr.AddManualWithScope(ctx, "66.249.70.6", ja4, "ip_ja4", "x", "tester", "deny", 0); err == nil {
		t.Fatal("manual BAN of a whitelisted IP should be refused")
	}

	// Hot-reload: swapping the closure (= an AdminSettingsSave) applies at once,
	// no restart.  Now only 9.9.9.9 is whitelisted.
	mgr.SetWhitelist(func(ip string) bool { return ip == "9.9.9.9" })
	mgr.AddWithSource(ctx, "66.249.70.7", ja4, SourceHoneypot, "", "")
	if !mgr.IsBanned(ctx, "66.249.70.7", ja4) {
		t.Fatal("after hot-reload the old CIDR is no longer whitelisted -> must ban")
	}
	mgr.AddWithSource(ctx, "9.9.9.9", ja4, SourceHoneypot, "", "")
	if mgr.IsBanned(ctx, "9.9.9.9", ja4) {
		t.Fatal("after hot-reload 9.9.9.9 is now whitelisted -> must not ban")
	}
}
