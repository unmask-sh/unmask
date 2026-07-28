package user

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func auditRepo(t *testing.T) *Repository {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "a.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return &Repository{DB: d}
}

// TestAuditRecordsClientIP: the trail said who / when / what but not from
// where, and nothing else on the box filled the gap -- nginx's admin access log
// keeps only the load-balancer hop, so on an LB-fronted node the operator's
// real address was written down nowhere.  That blocked configuring an admin IP
// allowlist (no way to learn which addresses legitimately reach the UI) and
// would block answering "which of these logins was not us" after an incident.
func TestAuditRecordsClientIP(t *testing.T) {
	r := auditRepo(t)
	ctx := WithClientIP(context.Background(), "203.0.113.9")
	r.Record(ctx, 1, "alice", "login", "", "")

	got, err := r.ListAudit(context.Background(), 10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	if !got[0].IP.Valid || got[0].IP.String != "203.0.113.9" {
		t.Errorf("IP = %+v, want the address the action came from", got[0].IP)
	}
	// The single-row read used by the restore handler must carry it too.
	one, err := r.GetAuditByID(context.Background(), got[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if one.IP.String != "203.0.113.9" {
		t.Errorf("GetAuditByID dropped the IP: %+v", one.IP)
	}
}

// TestAuditWithoutIPStillRecords: a caller with no request behind it (CLI,
// cron, the setup wizard before the middleware runs) has no client address.
// Recording "" would be a lie; the row must simply carry none, and must still
// be written -- an audit entry is worth more than the field it is missing.
func TestAuditWithoutIPStillRecords(t *testing.T) {
	r := auditRepo(t)
	r.Record(context.Background(), 0, "cli", "settings_save", "global", "{}")

	got, err := r.ListAudit(context.Background(), 10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the entry was dropped for want of an IP: %d rows", len(got))
	}
	if got[0].IP.Valid {
		t.Errorf("an absent IP was stored as a value: %+v", got[0].IP)
	}
	if got[0].Action != "settings_save" {
		t.Errorf("action = %q", got[0].Action)
	}
}

// TestClientIPContextRoundTrip: an empty IP must not put an empty value in the
// context, or a later reader cannot tell "no proxy resolved an address" from
// "the address is the empty string".
func TestClientIPContextRoundTrip(t *testing.T) {
	base := context.Background()
	if got := ClientIPFromContext(base); got != "" {
		t.Errorf("bare context yielded %q", got)
	}
	if got := ClientIPFromContext(WithClientIP(base, "")); got != "" {
		t.Errorf("empty IP stored a value: %q", got)
	}
	if got := ClientIPFromContext(WithClientIP(base, "2001:db8::1")); got != "2001:db8::1" {
		t.Errorf("round trip = %q", got)
	}
	//nolint:staticcheck // a nil context is what a mis-wired caller passes; it must not panic.
	if got := ClientIPFromContext(nil); got != "" {
		t.Errorf("nil context yielded %q", got)
	}
}
