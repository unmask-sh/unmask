package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/hll"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// "Non-human traffic" has to include the crawlers we let through on purpose.
// Counting only challenge failures left Googlebot -- unambiguously not a human,
// and on a public site usually the bigger half -- out of a figure named after
// exactly that, so the number read low and an operator comparing it against
// their access log would not have been able to reconcile the two.
//
// The split is what carries the meaning: benign is a configuration choice, and
// moving a crawler group onto a challenge is supposed to move it to the other
// side of the slash.  So both halves are asserted, not just the total.
func TestNonHumanTrafficCountsPassedCrawlersAsWellAsBlocked(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	// Seed the sketches the nginx-log pipeline writes.  Site-scoped, because
	// the install-wide view reads the pre-rolled aggregate table instead.
	const site = "example.com"
	if _, err := h.DB.Exec(`CREATE TABLE unmask_traffic_hll (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		kind VARCHAR(8) NOT NULL, sketch BLOB NOT NULL,
		PRIMARY KEY (bucket_min, site, kind))`); err != nil {
		t.Fatal(err)
	}
	sk := func(kind string, from, to int) {
		t.Helper()
		var sketch hll.Sketch
		for i := from; i < to; i++ {
			sketch.Add([]byte(fmt.Sprintf("10.0.%d.%d", i/256, i%256)))
		}
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_traffic_hll (site, bucket_min, kind, sketch) VALUES (?, ?, ?, ?)`,
			site, time.Now().Unix()/60, kind, sketch.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	// 1000 clients in all.  200 of them are listed crawlers we passed on
	// purpose; a separate 100 were challenged and never came back.
	sk("ip", 0, 1000)
	sk("ipb", 0, 200)
	sk("ipc", 500, 600)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"}) // assertions read the EN copy
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview: %d", rr.Code)
	}
	body := rr.Body.String()

	tile := regexp.MustCompile(`(?s)<div class="kpi">\s*<div class="label">Non-human traffic.*?<div class="value">(.*?)</div>.*?<div class="sub">(.*?)</div>`).
		FindStringSubmatch(body)
	if tile == nil {
		t.Fatal("the non-human tile is missing from the overview")
	}
	value, sub := tile[1], stripTags(tile[2])

	// HLL is approximate, so assert the shape rather than exact counts: both
	// halves present, and the percentage above what blocked alone would give.
	num := regexp.MustCompile(`([0-9]+) benign`).FindStringSubmatch(sub)
	if num == nil {
		t.Fatalf("the tile does not show a benign count: %q", sub)
	}
	if !strings.Contains(sub, "malicious") {
		t.Errorf("the tile does not show the malicious half: %q", sub)
	}
	pct := regexp.MustCompile(`([0-9.]+)%`).FindStringSubmatch(value)
	if pct == nil {
		t.Fatalf("the tile has no percentage: %q", value)
	}
	// blocked alone is ~10%; with the passed crawlers it is ~30%.  Anything at
	// or below 15 means benign was dropped from the numerator again.
	var got float64
	fmt.Sscanf(pct[1], "%f", &got)
	if got <= 15 {
		t.Errorf("non-human = %.1f%%, which is the blocked-only figure: the crawlers we passed are missing from the numerator (sub: %q)", got, sub)
	}
	if got > 60 {
		t.Errorf("non-human = %.1f%%, far above the seeded 30%%: the two halves are probably being double-counted (sub: %q)", got, sub)
	}
}

// The benign half is a consequence of the operator's own settings, not a
// property of the traffic, so the popover has to say so -- otherwise "benign
// bot" reads as unmask's verdict and the number looks broken the moment
// someone puts a crawler group behind a challenge and watches it switch sides.
func TestNonHumanPopoverExplainsBenignIsADeliberatePass(t *testing.T) {
	for _, tc := range []struct {
		lang i18n.Lang
		want []string
	}{
		{i18n.LangJA, []string{"意図的に素通し", "推定値", "GPTBot"}},
		{i18n.LangEN, []string{"deliberately lets through", "estimates", "GPTBot"}},
	} {
		help := i18n.T(tc.lang, "overview.kpi.nonhuman_help")
		if help == "" || help == "overview.kpi.nonhuman_help" {
			t.Fatalf("%s: the non-human popover copy is missing", tc.lang)
		}
		for _, w := range tc.want {
			if !strings.Contains(help, w) {
				t.Errorf("%s popover does not mention %q: %s", tc.lang, w, help)
			}
		}
	}
}

func stripTags(s string) string {
	return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, "")
}
