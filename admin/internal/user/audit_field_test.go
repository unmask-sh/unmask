package user

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// A failed login records the name it was sent, which the client chooses: a
// 3 MB name went into a row the audit keeps for good (SQLite does not hold
// a VARCHAR to its length, and MariaDB refused the row).  The name, the
// action and the target are cut to their columns, as valid UTF-8.
func TestAuditFieldsFitTheirColumns(t *testing.T) {
	r := auditRepo(t)
	long := strings.Repeat("a", 3<<20)
	r.Record(context.Background(), 0, long, "login_failed", strings.Repeat("ターゲット", 100), "")
	r.Record(context.Background(), 0, "bad\xffname", "login_failed", "", "")
	got, err := r.ListAudit(context.Background(), 10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d rows", len(got))
	}
	for _, e := range got {
		if n := utf8.RuneCountInString(e.Username); n > 64 || !utf8.ValidString(e.Username) {
			t.Errorf("username of %d characters, valid=%v", n, utf8.ValidString(e.Username))
		}
		if e.Target.Valid && (utf8.RuneCountInString(e.Target.String) > 128 || !strings.HasSuffix(e.Target.String, "…")) {
			t.Errorf("target %q", e.Target.String)
		}
	}
	if auditField("alice", 64) != "alice" {
		t.Error("a short name was changed")
	}
}
