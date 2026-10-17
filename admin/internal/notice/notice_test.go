package notice

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/n.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	return New(conn)
}

func ban(ip, source string, ts int64) map[string]any {
	return map[string]any{"event": KindBan, "ip": ip, "ja4": "t13d", "source": source, "reason": "hit /wp-login.php", "banned_by": "", "site": "blog", "ts": ts}
}

// Bans fold into one row per hour: the row counts them by source, names the
// latest and the last few addresses; the next hour starts a row.  The other
// kinds are a row each.
func TestBansFoldPerHour(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	h := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC).Unix()
	s.Add(KindBan, ban("203.0.113.1", "honeypot", h+10))
	s.Add(KindBan, ban("203.0.113.2", "honeypot", h+700))
	s.Add(KindBan, ban("203.0.113.3", "manual", h+3000))
	s.Add(KindBan, ban("203.0.113.1", "honeypot", h+3100)) // the same address again: named once
	s.Add(KindBan, ban("203.0.113.9", "honeypot", h+3600)) // the next hour
	s.Add(KindBurst, map[string]any{"event": KindBurst, "count_per_5m": int64(80), "threshold": int64(50), "site": "blog", "ts": h + 3700})
	s.Add("test_event", map[string]any{"event": "test_event"}) // the settings page's test send is not a notice

	rows, err := s.List(ctx, 1, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows: %d, want 3 (an hour of bans, the next hour, a burst): %+v", len(rows), rows)
	}
	if rows[0].Kind != KindBurst || rows[0].Severity != SeverityWarn || rows[0].Int("count_per_5m") != 80 || rows[0].Site != "blog" {
		t.Errorf("burst row: %+v", rows[0])
	}
	if rows[1].Kind != KindBan || rows[1].Events != 1 || rows[1].Str("ip") != "203.0.113.9" {
		t.Errorf("next hour's row: %+v", rows[1])
	}
	first := rows[2]
	if first.Events != 4 || first.CreatedAt != h+10 || first.UpdatedAt != h+3100 || first.Str("ip") != "203.0.113.1" || first.Str("source") != "honeypot" {
		t.Errorf("the hour's row: %+v", first)
	}
	src := first.Sources()
	if len(src) != 2 || src[0] != (SourceCount{"honeypot", 3}) || src[1] != (SourceCount{"manual", 1}) {
		t.Errorf("sources: %+v", src)
	}
	ips, _ := first.Detail["ips"].([]any)
	if len(ips) != 3 || ips[0] != "203.0.113.1" || ips[1] != "203.0.113.3" || ips[2] != "203.0.113.2" {
		t.Errorf("ips named, latest first, each once: %v", ips)
	}
	if n, _ := s.Count(ctx, 1, KindBan); n != 2 {
		t.Errorf("ban rows: %d", n)
	}
}

// A mark per account: unread is what is above it, opening the list moves it
// to the newest row, never back, and a row for one account is unread for that
// account alone.
func TestSeenMarkPerAccount(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	h := time.Now().Unix()
	s.Add(KindOverBlock, map[string]any{"event": KindOverBlock, "tripped": true, "stuck": int64(5), "ts": h - 100})
	s.Add(KindAdvisor, map[string]any{"event": KindAdvisor, "new_candidates": 2, "total_candidates": 7, "site": ""})
	alice, bob := int64(1), int64(2)
	if err := s.Put(ctx, Entry{Kind: KindOverBlock, UserID: &alice, Detail: map[string]any{"tripped": false}}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Unread(ctx, alice); n != 3 {
		t.Errorf("alice unread: %d, want 3", n)
	}
	if n, _ := s.Unread(ctx, bob); n != 2 {
		t.Errorf("bob unread: %d, want 2 (alice's row is not his)", n)
	}
	rows, _ := s.List(ctx, bob, "", 10, 0)
	if len(rows) != 2 || rows[0].Kind != KindAdvisor || rows[0].Severity != SeverityInfo || rows[1].Severity != SeverityCrit {
		t.Errorf("bob's rows: %+v", rows)
	}
	newest, _ := s.Newest(ctx, alice)
	if got, _ := s.MarkSeen(ctx, alice, newest); got != newest {
		t.Errorf("mark: %d, want %d", got, newest)
	}
	if n, _ := s.Unread(ctx, alice); n != 0 {
		t.Errorf("alice unread after opening the list: %d", n)
	}
	if n, _ := s.Unread(ctx, bob); n != 2 {
		t.Errorf("bob unread after alice read: %d", n)
	}
	if got, _ := s.MarkSeen(ctx, alice, newest-2); got != newest {
		t.Errorf("a stale mark moved the mark back: %d", got)
	}
	s.Add(KindBurst, map[string]any{"event": KindBurst, "count_per_5m": 60, "threshold": 50})
	if n, _ := s.Unread(ctx, alice); n != 1 {
		t.Errorf("alice unread after a new alert: %d", n)
	}
}

// The prune keeps retentionDays of rows, and drops the marks of accounts that
// are gone.
func TestPrune(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	s.Add(KindBurst, map[string]any{"event": KindBurst, "count_per_5m": 60, "threshold": 50, "ts": now - 100*86400})
	s.Add(KindBurst, map[string]any{"event": KindBurst, "count_per_5m": 60, "threshold": 50, "ts": now - 10*86400})
	if _, err := s.MarkSeen(ctx, 7, 1); err != nil { // no account 7
		t.Fatal(err)
	}
	n, err := s.Prune(ctx, 90)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if c, _ := s.Count(ctx, 1, ""); c != 1 {
		t.Errorf("rows after the prune: %d", c)
	}
	if id, _ := s.SeenID(ctx, 7); id != 0 {
		t.Errorf("the mark of a gone account survived: %d", id)
	}
	if n, _ := s.Prune(ctx, 0); n != 0 {
		t.Errorf("retention 0 deleted %d", n)
	}
}

// Nil-safe: a daemon with no database has a nil store.
func TestNilStore(t *testing.T) {
	var s *Store
	s.Add(KindBan, ban("1.2.3.4", "manual", 0))
	if n, err := s.Unread(context.Background(), 1); n != 0 || err != nil {
		t.Error("nil store")
	}
}

// TestNoticeKeptWhileWritesAreHeld: a notice that cannot be written -- the
// database's writes held, or busy past the deadline -- is kept and written
// when it can be, not lost.
func TestNoticeKeptWhileWritesAreHeld(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	h := time.Date(2026, 10, 17, 21, 0, 0, 0, time.UTC).Unix()
	s.DB.HoldWrites(true)
	s.Add(KindBan, ban("203.0.113.5", "honeypot", h+10))
	if rows, _ := s.List(ctx, 1, "", 50, 0); len(rows) != 0 {
		t.Fatalf("written while writes were held: %+v", rows)
	}
	s.RetryHeld() // under the hold: tries nothing
	if rows, _ := s.List(ctx, 1, "", 50, 0); len(rows) != 0 {
		t.Fatalf("a retry under the hold wrote: %+v", rows)
	}
	s.DB.HoldWrites(false)
	if n := s.RetryHeld(); n != 0 {
		t.Errorf("%d still kept after the retry", n)
	}
	rows, err := s.List(ctx, 1, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Kind != KindBan || rows[0].Str("ip") != "203.0.113.5" || rows[0].CreatedAt != h+10 {
		t.Errorf("after the retry: %+v, want the kept ban notice with its own time", rows)
	}
}
