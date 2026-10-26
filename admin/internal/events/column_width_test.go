package events

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A value is cut to its column's width in runes, not bytes, and made valid
// UTF-8: a utf8mb4 column refuses a bare byte, and a cut through a multibyte
// character would leave one.
func TestFitCutsToRunesAndDropsInvalidUTF8(t *testing.T) {
	long := strings.Repeat("あ", 300) // 300 runes, 900 bytes
	if got := fit(long, 255); utf8.RuneCountInString(got) != 255 || !utf8.ValidString(got) {
		t.Errorf("fit of 300 runes to 255: %d runes, valid %v", utf8.RuneCountInString(got), utf8.ValidString(got))
	}
	if got := fit("abc", 255); got != "abc" {
		t.Errorf("fit within the width changed the value: %q", got)
	}
	if got := fit("abcdef", 3); got != "abc" {
		t.Errorf("fit of ascii: %q", got)
	}
	if got := fit("a\xffb\xfe", 10); got != "ab" {
		t.Errorf("fit kept invalid bytes: %q", got)
	}
	if got := fit("\xff"+strings.Repeat("x", 5), 3); got != "xxx" {
		t.Errorf("fit must drop the invalid byte before counting: %q", got)
	}
	if got := fit(long, 0); got != long {
		t.Error("a width of 0 means no width")
	}
}

// The writer cuts every string column to its width, so a row is never
// refused for a value a client sent.
func TestPrepareInsertArgsFitsEveryStringColumn(t *testing.T) {
	e := &Event{
		Site:       strings.Repeat("s", 100),
		Host:       strings.Repeat("h", 100),
		UserAgent:  strings.Repeat("u", 300) + "\xff",
		JA4:        strings.Repeat("j", 50),
		JA4Verdict: strings.Repeat("v", 50),
		Phase:      "serve",
		CookieBV:   strings.Repeat("c", 2000),
		CookieBR:   strings.Repeat("b", 20),
		IPPacked:   []byte{192, 0, 2, 1},
	}
	args := prepareInsertArgs(e)
	if args == nil {
		t.Fatal("a valid event produced no args")
	}
	str := func(v any) string {
		switch x := v.(type) {
		case string:
			return x
		case sql.NullString:
			return x.String
		}
		t.Fatalf("unexpected arg type %T", v)
		return ""
	}
	// site, host, scheme, port, ip, ua, ja4, verdict, verdict_id, phase,
	// flags, reload, cookie_bv, cookie_br, payload, ref, date
	for i, want := range map[int]int{0: widthSite, 1: widthHost, 5: widthUserAgent, 6: widthJA4, 7: widthVerdict, 12: CookieBVWidth, 13: widthCookieBR} {
		if got := utf8.RuneCountInString(str(args[i])); got != want {
			t.Errorf("arg %d: %d runes, want the column's %d", i, got, want)
		}
	}
	if !utf8.ValidString(str(args[5])) {
		t.Error("the user agent kept an invalid byte")
	}
}

// On SQLite the catalog has no width to read and the cut stays at what the
// beacon reads; the read is a no-op that leaves the full width in force.
func TestLoadColumnWidthsOnSQLite(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cookieBVWidth.Store(cookieBVWidthShipped)
	LoadColumnWidths(context.Background(), d)
	if got := cookieBVWidth.Load(); got != CookieBVWidth {
		t.Errorf("width after the read on SQLite: %d, want %d", got, CookieBVWidth)
	}
	if _, ok, err := d.ColumnCharLength(context.Background(), "unmask_event", "cookie_bv"); ok || err != nil {
		t.Errorf("SQLite reported a width: ok=%v err=%v", ok, err)
	}
	LoadColumnWidths(context.Background(), nil)
	if got := cookieBVWidth.Load(); got != CookieBVWidth {
		t.Errorf("width after the read with no database: %d, want %d", got, CookieBVWidth)
	}
}

// A refusal for the row's own data is told apart from the state of the
// database: the first is written around, the second retried.
func TestIsDataError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{&mysql.MySQLError{Number: 1406, Message: "Data too long for column 'cookie_bv' at row 1"}, true},
		{&mysql.MySQLError{Number: 1366, Message: "Incorrect string value"}, true},
		{&mysql.MySQLError{Number: 1265, Message: "Data truncated"}, true},
		{&mysql.MySQLError{Number: 1264, Message: "Out of range value"}, true},
		{&mysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"}, false},
		{&mysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"}, false},
		{&mysql.MySQLError{Number: 2006, Message: "MySQL server has gone away"}, false},
		{errors.New("database is locked (5) (SQLITE_BUSY)"), false},
		{context.DeadlineExceeded, false},
		{errors.New("constraint failed: Data too long for column test (19)"), true},
		{errors.New("Error 1366: Incorrect string value: '\\xFF' for column 'ua'"), true},
	} {
		if got := isDataError(c.err); got != c.want {
			t.Errorf("isDataError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// A batch the database refuses for one row's data is written row by row:
// the row is dropped and counted, the rest of the batch lands, and the
// flusher does not keep retrying the same batch.  A trigger stands in for
// MariaDB's strict mode: SQLite enforces no width of its own.
func TestFlushWritesTheBatchAroundARowTheDatabaseRefuses(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TRIGGER refuse_poison BEFORE INSERT ON unmask_event
		WHEN NEW.user_agent = 'poison'
		BEGIN SELECT RAISE(ABORT, 'Data too long for column user_agent'); END`); err != nil {
		t.Fatal(err)
	}
	f := NewFlusher(d, 100, 100)
	for _, ua := range []string{"first", "poison", "third", "poison", "fifth"} {
		f.Submit(&Event{Site: "s", Phase: "serve", UserAgent: ua, IPPacked: []byte{192, 0, 2, 1}})
	}
	deadline := time.Now().Add(10 * time.Second)
	var n int
	for {
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.Stop()
	if n != 3 {
		t.Fatalf("%d rows written, want the 3 the database did not refuse", n)
	}
	if got := f.DroppedBadRowsCount(); got != 2 {
		t.Errorf("%d rows counted as refused, want 2", got)
	}
	if got := f.DroppedOnErrorCount(); got != 0 {
		t.Errorf("%d rows counted as dropped on error, want none: the rows were written around, not retried", got)
	}
	var uas []string
	rows, err := d.Query(`SELECT user_agent FROM unmask_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ua string
		if err := rows.Scan(&ua); err != nil {
			t.Fatal(err)
		}
		uas = append(uas, ua)
	}
	if strings.Join(uas, ",") != "first,third,fifth" {
		t.Errorf("rows written: %v, want first, third and fifth in order", uas)
	}
}
