package ban

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Three automatic bans on distinct addresses of one IPv6 /64 inside a day
// widen to the /64: an ip_only row on the prefix, with the action and the
// lifetime of the ban that tipped it.  Two do not; a fourth adds nothing;
// an operator's bans do not count; another /64 is untouched.
func TestAutoBansEscalateToThe64(t *testing.T) {
	_, mgr, banFile := openMirrorTest(t)
	ctx := context.Background()
	created := []string{}
	mgr.OnCreated = func(ip, ja4, source, reason, bannedBy string) { created = append(created, ip+" "+reason) }

	mgr.AddWithSourceAction(ctx, "2001:db8:1:2::a", "t13d_a", SourceHoneypot, "trap", "", "captcha_only")
	mgr.AddWithSourceAction(ctx, "2001:db8:1:2::b", "", SourceHoneypot, "trap", "", "captcha_only")
	if _, _, b := mgr.IsBannedActionSource(ctx, "2001:db8:1:2::ffff", "t13d_zzz"); b {
		t.Fatal("the /64 was widened after two addresses")
	}
	// An operator's ban in the same /64 does not count toward it.
	if err := mgr.AddManualWithScope(ctx, "2001:db8:1:2::c", "", ScopeIPOnly, "by hand", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if _, _, b := mgr.IsBannedActionSource(ctx, "2001:db8:1:2::ffff", "t13d_zzz"); b {
		t.Fatal("the operator's ban counted toward the /64")
	}
	mgr.AddWithSourceAction(ctx, "2001:db8:1:2::d", "t13d_d", SourceHoneypot, "trap", "", "captcha_only")
	action, source, b := mgr.IsBannedActionSource(ctx, "2001:db8:1:2::ffff", "t13d_zzz")
	if !b || source != SourceHoneypot || action != "captcha_only" {
		t.Fatalf("after three addresses: banned=%v source=%q action=%q, want the /64's honeypot captcha_only ban", b, source, action)
	}
	if _, _, b := mgr.IsBannedActionSource(ctx, "2001:db8:1:2:ffff:ffff:ffff:ffff", ""); !b {
		t.Error("the /64 ban does not hold on a JA4-less check")
	}
	if _, _, b := mgr.IsBannedActionSource(ctx, "2001:db8:1:3::1", "t13d_zzz"); b {
		t.Error("the escalation reached the next /64")
	}
	mgr.settle()
	buf, _ := os.ReadFile(banFile)
	if !strings.Contains(string(buf), "2001:db8:1:2::/64||honeypot|captcha_only\n") {
		t.Errorf("the ban file carries no line for the /64:\n%s", buf)
	}
	// Announced once, with its reason.
	n := 0
	for _, c := range created {
		if strings.HasPrefix(c, "2001:db8:1:2::/64 ") {
			n++
			if !strings.Contains(c, "escalated: 3 addresses in the same /64 were banned within a day") {
				t.Errorf("the /64 ban's reason: %q", c)
			}
		}
	}
	if n != 1 {
		t.Errorf("the /64 ban was announced %d times", n)
	}
	// A fourth address widens nothing further: one row on the /64.
	mgr.AddWithSourceAction(ctx, "2001:db8:1:2::e", "", SourceHoneypot, "trap", "", "captcha_only")
	rows := 0
	for _, e := range mgr.Snapshot() {
		if e.IP == "2001:db8:1:2::/64" {
			rows++
			if e.Scope != ScopeIPOnly || e.JA4 != "" || e.Source != SourceHoneypot || e.Action != "captcha_only" || e.ExpiresAt.IsZero() {
				t.Errorf("the /64 row: %+v", e)
			}
		}
	}
	if rows != 1 {
		t.Errorf("%d rows on the /64, want 1", rows)
	}
	// The more specific row wins over the prefix.
	if err := mgr.AddManualWithScope(ctx, "2001:db8:1:2::9", "", ScopeIPOnly, "by hand", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if action, _, _ := mgr.IsBannedActionSource(ctx, "2001:db8:1:2::9", "t13d_zzz"); action != "deny" {
		t.Errorf("the address's own row lost to the /64: action %q", action)
	}
}

// An operator may ban a prefix by hand, as an ip_only row; it is matched by
// containment, after the exact rows, and written as "<addr>/<len>|".
func TestManualPrefixBan(t *testing.T) {
	d, mgr, banFile := openMirrorTest(t)
	ctx := context.Background()
	if err := mgr.AddManualWithScope(ctx, "203.0.113.77/24", "", ScopeIPOnly, "the whole /24", "op", "captcha_only", 0); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddManualWithScope(ctx, "2001:DB8:1:2:3:4:5:6/64", "", "", "typed with the host bits", "op", "", 0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip, ja4 string
		want    bool
	}{
		{"203.0.113.9", "t13d_a", true},
		{"203.0.113.9", "", true},
		{"::ffff:203.0.113.9", "", true},
		{"203.0.114.9", "t13d_a", false},
		{"2001:db8:1:2::1", "t13d_a", true},
		{"2001:db8:1:3::1", "t13d_a", false},
	} {
		if got := mgr.IsBanned(ctx, c.ip, c.ja4); got != c.want {
			t.Errorf("IsBanned(%q, %q) = %v, want %v", c.ip, c.ja4, got, c.want)
		}
	}
	mgr.settle()
	buf, _ := os.ReadFile(banFile)
	for _, want := range []string{"203.0.113.0/24||manual|captcha_only\n", "2001:db8:1:2::/64||manual|deny\n"} {
		if !strings.Contains(string(buf), want) {
			t.Errorf("the file lacks %q:\n%s", want, buf)
		}
	}
	var ip string
	if err := d.QueryRow(`SELECT ip FROM unmask_ban WHERE ip LIKE '2001:%'`).Scan(&ip); err != nil || ip != "2001:db8:1:2::/64" {
		t.Errorf("the prefix is stored as %q (%v), want masked and lower-case", ip, err)
	}
	// A prefix bans addresses: it takes no fingerprint beside it.
	if err := mgr.AddManualWithScope(ctx, "203.0.113.0/24", "t13d_a", ScopeIPJA4, "x", "op", "", 0); err == nil {
		t.Error("a prefix with a fingerprint under ip_ja4 was accepted")
	}
	if err := mgr.AddManualWithScope(ctx, "203.0.113.0/33", "", ScopeIPOnly, "x", "op", "", 0); err == nil {
		t.Error("an invalid prefix was accepted")
	}
	// Kept during a hold, a prefix ban holds by containment too.
	d.HoldWrites(true)
	defer d.HoldWrites(false)
	if err := mgr.AddManualWithScope(ctx, "198.51.100.0/24", "", ScopeIPOnly, "x", "op", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if !mgr.IsBanned(ctx, "198.51.100.200", "t13d_a") || mgr.IsBanned(ctx, "198.51.101.1", "t13d_a") {
		t.Error("the kept prefix ban is not matched by containment")
	}
}
