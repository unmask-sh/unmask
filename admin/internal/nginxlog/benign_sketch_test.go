package nginxlog

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The benign half of the overview's non-human split is a per-site request
// counter, and it has to survive the flush -- not just reach the in-memory
// bucket.
//
// This is asserted against the table because flush copies buckets field by
// field in three places, and the first version of this signal (an HLL sketch)
// was added to the bump path and the persist loop but to none of those: every
// unit-level check passed and the fleet wrote not one row.  Anything that reads
// the in-memory bucket would repeat the mistake.
func TestBenignCrawlerCounterSurvivesFlush(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	r := &Reader{
		d: d, buckets: map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		countryHourlyBuckets: map[countryHourKey]*countryHourBucket{},
		cookieIPBuckets:      map[cookieIPKey]*cookieIPBucket{},
	}
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") || strings.Contains(ua, "GPTBot") {
			return "search"
		}
		return ""
	})

	line := func(fc int, ip, ua string) string {
		return fmt.Sprintf("1754000000.000 site=s kind= fc=%d hp=0 ip=%s ja4=- hpuri=- ua=%s", fc, ip, ua)
	}
	// Drive the real parse path so the counter is proved end to end.
	for _, l := range []string{
		line(0, "1.1.1.1", "Mozilla/5.0 (compatible; Googlebot/2.1)"),  // passed crawler -> benign
		line(0, "1.1.1.2", "Mozilla/5.0 (compatible; Googlebot/2.1)"),  // ditto
		line(1, "2.2.2.2", "Mozilla/5.0 (compatible; GPTBot/1.3)"),     // challenged crawler -> not benign
		line(0, "3.3.3.3", "Mozilla/5.0 (Windows NT 10.0) Chrome/120"), // ordinary visitor
	} {
		r.onLine(l)
	}
	r.flushOnce(true)

	get := func(kind string) int {
		var n int
		if err := d.QueryRowContext(context.Background(),
			`SELECT COALESCE(SUM(cnt),0) FROM unmask_cookie_minute WHERE kind = ?`, kind).Scan(&n); err != nil {
			t.Fatalf("read %s: %v", kind, err)
		}
		return n
	}
	if got := get("crawler_pass"); got != 2 {
		t.Errorf("crawler_pass = %d, want 2 (the two passed Googlebot requests only)", got)
	}
	// Bump owns "total": one row per access-log line.  A second counter for the
	// same line must not inflate it, or the non-human ratio's denominator grows
	// every time a crawler is seen.
	if got := get("total"); got != 4 {
		t.Errorf("total = %d, want 4 (one per log line): the benign counter is double-counting requests", got)
	}
	if got := get("challenge_served"); got != 1 {
		t.Errorf("challenge_served = %d, want 1 (the GPTBot we challenged)", got)
	}
}

// A request a bypass rule let through has to be countable.  The access log
// could not say so -- fc is 0 for "bypassed" and for "matched nothing" alike --
// so the dashboard put package managers fetching a repo behind a bypass path
// into its human share: 30% of all traffic on one install.
//
// The field is optional in the parser on purpose: the binary is deployed
// before the config that emits it, and every line written in that window has
// to keep parsing.
func TestBypassMarkerIsCountedAndOptional(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := &Reader{
		d: d, buckets: map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		countryHourlyBuckets: map[countryHourKey]*countryHourBucket{},
		cookieIPBuckets:      map[cookieIPKey]*cookieIPBucket{},
	}
	// Two bypassed requests, one ordinary, one challenged-while-bypassed (which
	// cannot happen in nginx but must not double-count if it ever does), and one
	// line in the old shape with no bp= field at all.
	for _, l := range []string{
		"1754000000.000 site=s kind= fc=0 hp=0 ip=1.1.1.1 ja4=- hpuri=- bp=1 ua=libdnf",
		"1754000000.000 site=s kind= fc=0 hp=0 ip=1.1.1.2 ja4=- hpuri=- bp=1 ua=curl/8.0",
		"1754000000.000 site=s kind= fc=0 hp=0 ip=1.1.1.3 ja4=- hpuri=- bp=0 ua=Mozilla/5.0",
		"1754000000.000 site=s kind= fc=1 hp=0 ip=1.1.1.4 ja4=- hpuri=- bp=1 ua=curl/8.0",
		"1754000000.000 site=s kind= fc=0 hp=0 ip=1.1.1.5 ja4=- hpuri=- ua=Mozilla/5.0",
	} {
		r.onLine(l)
	}
	r.flushOnce(true)

	get := func(kind string) int {
		var n int
		if err := d.QueryRowContext(context.Background(),
			`SELECT COALESCE(SUM(cnt),0) FROM unmask_cookie_minute WHERE kind = ?`, kind).Scan(&n); err != nil {
			t.Fatalf("read %s: %v", kind, err)
		}
		return n
	}
	if got := get("bypass_pass"); got != 2 {
		t.Errorf("bypass_pass = %d, want 2 (the two passed bypass lines only)", got)
	}
	if got := get("total"); got != 5 {
		t.Errorf("total = %d, want 5 -- one per line, including the one with no bp= field", got)
	}
	if got := get("challenge_served"); got != 1 {
		t.Errorf("challenge_served = %d, want 1", got)
	}
}
