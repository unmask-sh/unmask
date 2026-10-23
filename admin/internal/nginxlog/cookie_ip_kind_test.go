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

	r.bumpCookieIP("s1", "1.2.3.4", "t13d_a", "UA-A", "captcha", true)
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_b", "UA-B", "pow", true)
	// A line the gate did not judge (a static file outside the protected
	// locations, a challenge-page part): counted in the whole, not in judged.
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_b", "UA-B", "pow", false)
	// Not a reused cookie: a challenge being served writes an unmask_event row
	// of its own, and "" is no cookie at all.  Neither belongs in a reuse count.
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_c", "UA-C", "challenge_served", true)
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_c", "UA-C", "", true)
	// No IP -> nothing to rank.
	r.bumpCookieIP("s1", "", "t13d_d", "UA-D", "pow", true)

	r.flushOnce(true)

	got, judged := map[string]int{}, map[string]int{}
	rows, err := d.Query(`SELECT kind, SUM(cnt), SUM(judged) FROM unmask_cookie_ip_minute GROUP BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n, j int
		if err := rows.Scan(&k, &n, &j); err != nil {
			t.Fatal(err)
		}
		got[k], judged[k] = n, j
	}
	if len(got) != 2 || got["captcha"] != 1 || got["pow"] != 2 {
		t.Fatalf("stored kinds = %v, want exactly captcha:1 pow:2", got)
	}
	if judged["captcha"] != 1 || judged["pow"] != 1 {
		t.Fatalf("judged = %v, want captcha:1 pow:1 (the unjudged line is in the whole only)", judged)
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
