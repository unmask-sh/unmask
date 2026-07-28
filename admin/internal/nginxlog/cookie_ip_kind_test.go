package nginxlog

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func cookieIPReader(t *testing.T) (*Reader, *db.DB) {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return &Reader{d: d, cookieIPBuckets: map[cookieIPKey]*cookieIPBucket{}}, d
}

// TestCookieIPRecordsBothKinds: a request carrying a valid _bv cookie writes no
// unmask_event row (no challenge fires), so this table is the only record of a
// client riding one solved cookie.  It used to keep CAPTCHA cookies only, which
// left the PoW case -- the transparent challenge a headless scraper can solve
// cheaply -- invisible in every view.  Both kinds must land, separately.
func TestCookieIPRecordsBothKinds(t *testing.T) {
	r, d := cookieIPReader(t)

	r.bumpCookieIP("s1", "1.2.3.4", "t13d_a", "UA-A", "captcha")
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_b", "UA-B", "pow")
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_b", "UA-B", "pow")
	// Not a reused cookie: a challenge being served writes an unmask_event row
	// of its own, and "" is no cookie at all.  Neither belongs in a reuse count.
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_c", "UA-C", "challenge_served")
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_c", "UA-C", "")
	// No IP -> nothing to rank.
	r.bumpCookieIP("s1", "", "t13d_d", "UA-D", "pow")

	r.flushOnce(true)

	got := map[string]int{}
	rows, err := d.Query(`SELECT kind, SUM(cnt) FROM unmask_cookie_ip_minute GROUP BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		got[k] = n
	}
	if len(got) != 2 || got["captcha"] != 1 || got["pow"] != 2 {
		t.Fatalf("stored kinds = %v, want exactly captcha:1 pow:2", got)
	}

	// The two kinds must not collapse into one row: the PK carries kind, so the
	// same IP in the same minute keeps a separate counter per kind.  Without
	// that the PoW volume would silently accumulate onto the CAPTCHA row and
	// make an ordinary visitor look like a CAPTCHA-riding scraper.
	var nrows int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_ip_minute`).Scan(&nrows); err != nil {
		t.Fatal(err)
	}
	if nrows != 2 {
		t.Errorf("row count = %d, want 2 (one per kind for the same IP-minute)", nrows)
	}

	// ja4 / ua stay per-kind too, so the read side attributes the right
	// fingerprint to each section.
	var ja4 string
	if err := d.QueryRow(`SELECT ja4 FROM unmask_cookie_ip_minute WHERE kind='captcha'`).Scan(&ja4); err != nil {
		t.Fatal(err)
	}
	if ja4 != "t13d_a" {
		t.Errorf("captcha row ja4 = %q, want the captcha line's fingerprint", ja4)
	}
}
