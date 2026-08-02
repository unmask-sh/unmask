package nginxlog

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/hll"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The benign half of the overview's non-human split comes from the 'ipb'
// sketch, and it has to survive the flush -- not just reach the in-memory
// bucket.
//
// This is asserted end-to-end because flush copies the bucket field by field
// in three places (hand-off, retry-restore, retry-merge), and the first cut of
// ipb was added to bumpTrafficHLL and to the persist loop but to none of
// those.  Every unit-level check passed; on the fleet, not one 'ipb' row was
// ever written.  Anything that reads the in-memory sketch would have repeated
// the mistake, so the assertion is on the table.
func TestBenignCrawlerSketchSurvivesFlush(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	r := &Reader{d: d, buckets: map[bucketKey]*bucket{}, crawlerBuckets: map[crawlerKey]*crawlerBucket{}}
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") || strings.Contains(ua, "GPTBot") {
			return "search"
		}
		return ""
	})

	const gbot = "Mozilla/5.0 (compatible; Googlebot/2.1)"
	const gpt = "Mozilla/5.0 (compatible; GPTBot/1.3)"
	const chrome = "Mozilla/5.0 (Windows NT 10.0) Chrome/120"

	r.bumpTrafficHLL("s", "1.1.1.1", false, "", gbot)   // listed crawler, passed -> benign
	r.bumpTrafficHLL("s", "1.1.1.2", false, "", gbot)   // ditto, second address
	r.bumpTrafficHLL("s", "2.2.2.2", true, "", gpt)     // listed crawler we CHALLENGED -> not benign
	r.bumpTrafficHLL("s", "3.3.3.3", false, "", chrome) // ordinary visitor -> not benign
	r.bumpTrafficHLL("s", "4.4.4.4", false, "", "")     // no UA -> not benign

	r.flushOnce(true)

	kinds := map[string]bool{}
	rows, err := d.QueryContext(context.Background(), `SELECT kind FROM unmask_traffic_hll`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		kinds[k] = true
	}
	rows.Close()
	if !kinds["ipb"] {
		t.Fatalf("no 'ipb' row was written, so the benign half of the split is permanently 0 (kinds present: %v)", kinds)
	}

	// A challenged crawler belongs on the malicious side: an operator who puts
	// the AI-crawler group behind a challenge is not letting GPTBot through,
	// and the tile must not keep counting it as if they were.
	est := func(kind string) int {
		var blob []byte
		if err := d.QueryRowContext(context.Background(),
			`SELECT sketch FROM unmask_traffic_hll WHERE kind = ?`, kind).Scan(&blob); err != nil {
			t.Fatalf("read %s: %v", kind, err)
		}
		return hll.Load(blob).Estimate()
	}
	if got := est("ipb"); got != 2 {
		t.Errorf("benign = %d, want 2 (the two passed Googlebot addresses only)", got)
	}
	if got := est("ipc"); got != 1 {
		t.Errorf("challenged = %d, want 1 (the GPTBot we challenged)", got)
	}
}
