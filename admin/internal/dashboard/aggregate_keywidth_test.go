package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// mariadbColumnWidth is the width the MariaDB migrations leave a VARCHAR
// column of a table with: the last one a CREATE TABLE or a MODIFY of the
// numbered files declares.
func mariadbColumnWidth(t *testing.T, table, column string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "db", "migrations", "mariadb", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no MariaDB migrations to read: %v", err)
	}
	sort.Strings(files)
	create := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + table + `\s*\((.*)`)
	alter := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table + `\s+(.*)`)
	col := regexp.MustCompile(`(?im)(?:^|MODIFY\s+(?:COLUMN\s+)?|ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?)\s*` + column + `\s+VARCHAR\s*\(\s*(\d+)\s*\)`)
	width := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Comment lines out, then statement by statement.
		var kept []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				kept = append(kept, l)
			}
		}
		for _, stmt := range strings.Split(strings.Join(kept, "\n"), ";") {
			body := ""
			if m := create.FindStringSubmatch(stmt); m != nil {
				body = m[1]
			} else if m := alter.FindStringSubmatch(stmt); m != nil {
				body = m[1]
			}
			if m := col.FindStringSubmatch(body); m != nil {
				width, _ = strconv.Atoi(m[1])
			}
		}
	}
	if width == 0 {
		t.Fatalf("the MariaDB migrations declare no width for %s.%s", table, column)
	}
	return width
}

// TestRollupKeyWidthIsTheColumns: the width the fold cuts a key to is the
// one MariaDB's two rollup tables have.  A fold that cut to more would be
// refused there, the chunk's transaction and its cursor with it.
func TestRollupKeyWidthIsTheColumns(t *testing.T) {
	for _, table := range []string{"unmask_aggregate_hourly", "unmask_aggregate_hll"} {
		if w := mariadbColumnWidth(t, table, "bucket_key"); w != bucketKeyWidth {
			t.Errorf("%s.bucket_key is VARCHAR(%d) on MariaDB; the fold cuts a key to %d", table, w, bucketKeyWidth)
		}
	}
}

// TestFoldCutsAKeyToTheColumn: a rollup key is written within the column's
// width whatever the events hold -- an entry of the length the beacon keeps
// is there whole, a longer one is cut on a character, and two that the cut
// makes one are one row holding both.
func TestFoldCutsAKeyToTheColumn(t *testing.T) {
	d := openTestDB(t)
	defer hourlyReady.Store(false)
	ctx := context.Background()

	entry := "own:" + strings.Repeat("python-requests|", 9) + "curl/x" // 154 characters
	long := "own:" + strings.Repeat("あ", 300)                          // past the width, in three-byte characters
	insert := func(ip, rule string) {
		t.Helper()
		if _, err := d.Exec(
			`INSERT INTO unmask_event (site, host, ip_address, user_agent, phase, payload_json, date_created)
			 VALUES ('a.example','h', ?, 'UA', 'load', ?, datetime('now','-30 minutes'))`,
			[]byte(ip), `{"force_reason":"ua_target","force_rule":"`+rule+`"}`); err != nil {
			t.Fatal(err)
		}
	}
	insert("\x01\x02\x03\x04", entry)
	insert("\x01\x02\x03\x05", long+"-one")
	insert("\x01\x02\x03\x06", long+"-two") // the same key once cut
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("fold: %v", err)
	}

	rows, err := d.Query(`SELECT bucket_key, cnt FROM unmask_aggregate_hourly WHERE bucket_kind = ?`, hkCaptchaForceRule)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(k) || utf8.RuneCountInString(k) > bucketKeyWidth {
			t.Errorf("a key of %d characters was written; the column holds %d", utf8.RuneCountInString(k), bucketKeyWidth)
		}
		got[k] = n
	}
	cut := "ua_target|own:" + strings.Repeat("あ", bucketKeyWidth-len("ua_target|own:"))
	if len(got) != 2 || got["ua_target|"+entry] != 1 || got[cut] != 2 {
		t.Errorf("the rollup holds %d key(s): the whole entry %d time(s), the cut one %d; want 2 keys, 1 and 2",
			len(got), got["ua_target|"+entry], got[cut])
	}
	// The sketches under the same keys: the cut one holds both addresses.
	var sketch []byte
	if err := d.QueryRow(`SELECT sketch FROM unmask_aggregate_hll WHERE bucket_kind = ? AND bucket_key = ?`,
		hkCaptchaForceRuleIP, cut).Scan(&sketch); err != nil {
		t.Fatalf("the sketch under the cut key: %v", err)
	}
	if n := loadHLL(sketch).estimate(); n != 2 {
		t.Errorf("the sketch under the cut key counts %d address(es), want 2", n)
	}
}
