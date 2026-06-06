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
	mgr := New(d, banFile, 0, nil)
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
	mgr := New(d, banFile, 0, nil)
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
	mgr := New(d, banFile, 0, nil)
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
	mgr := New(d, banFile, 0, nil)
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
	mgr := New(d, "", 0, nil)
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
	mgr := New(d, banFile, 0, nil)
	if err := mgr.AddManual(context.Background(), "1.2.3.4", "", "scan", "tester", "", 0); err != nil {
		t.Fatalf("AddManual(ip=1.2.3.4, ja4=empty): %v", err)
	}
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), "1.2.3.4||manual|deny") {
		t.Errorf("ban file lacks ip-only row\n---file---\n%s", string(buf))
	}
}
