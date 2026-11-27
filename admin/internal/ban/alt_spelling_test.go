package ban

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestAltSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.5":        "::ffff:203.0.113.5",
		"::ffff:203.0.113.5": "203.0.113.5",
		"::ffff:cb00:7105":   "203.0.113.5", // the same address, in hexadecimal
		"2001:db8::1":        "",
		"::1":                "",
		"203.0.113.0/24":     "",
		"":                   "",
		"not an address":     "",
	} {
		if got := altSpelling(in); got != want {
			t.Errorf("altSpelling(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestASingleAddressBanHoldsInEitherSpelling: a ban on one IPv4 address
// holds on the client whether nginx hands it over as "203.0.113.5" or as
// "::ffff:203.0.113.5" (an IPv6 socket that takes both families, a proxy
// that writes it so), whichever of the two the ban was typed as -- the
// address row, the address-and-fingerprint row, and a ban kept through a
// schema update's hold.  They were matched by their text, so the one
// spelling stepped around a ban on the other, while a prefix around the
// same address held.
func TestASingleAddressBanHoldsInEitherSpelling(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr := New(d, "", time.Hour)
	const ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(mgr.AddManualWithScope(ctx, "203.0.113.5", "", ScopeIPOnly, "typed as IPv4", "op", "deny", 0))
	must(mgr.AddManualWithScope(ctx, "::ffff:198.51.100.7", "", ScopeIPOnly, "typed v4-mapped", "op", "captcha_only", 0))
	must(mgr.AddManualWithScope(ctx, "192.0.2.9", ja4, ScopeIPJA4, "an address and a fingerprint", "op", "deny", 0))
	must(mgr.AddManualWithScope(ctx, "2001:db8::5", "", ScopeIPOnly, "an IPv6 address", "op", "deny", 0))

	for _, c := range []struct {
		ip, ja4 string
		want    string // the action, "" = not banned
	}{
		{"203.0.113.5", "", "deny"},
		{"::ffff:203.0.113.5", "", "deny"},
		{"203.0.113.5", ja4, "deny"},
		{"::ffff:203.0.113.5", ja4, "deny"},
		{"198.51.100.7", "", "captcha_only"},
		{"::ffff:198.51.100.7", ja4, "captcha_only"},
		{"192.0.2.9", ja4, "deny"},
		{"::ffff:192.0.2.9", ja4, "deny"},
		{"::ffff:192.0.2.9", "t13d_another", ""}, // the row names the fingerprint too
		{"2001:db8::5", "", "deny"},
		{"203.0.113.6", "", ""},
		{"::ffff:203.0.113.6", ja4, ""},
	} {
		action, _, banned := mgr.IsBannedActionSource(ctx, c.ip, c.ja4)
		if banned != (c.want != "") || (banned && action != c.want) {
			t.Errorf("%s with fingerprint %q: banned=%v action=%q, want %q", c.ip, c.ja4, banned, action, c.want)
		}
	}

	// A ban kept while the database's writes are held is matched the same.
	d.HoldWrites(true)
	must(mgr.AddManualWithScope(ctx, "203.0.113.77", "", ScopeIPOnly, "placed during the hold", "op", "deny", 0))
	for _, ip := range []string{"203.0.113.77", "::ffff:203.0.113.77"} {
		if !mgr.IsBanned(ctx, ip, "") || !mgr.IsBanned(ctx, ip, ja4) {
			t.Errorf("%s is not held by the ban kept during the hold", ip)
		}
	}
	if mgr.IsBanned(ctx, "::ffff:203.0.113.78", "") {
		t.Error("::ffff:203.0.113.78 is held by a kept ban on another address")
	}
	d.HoldWrites(false)
}
