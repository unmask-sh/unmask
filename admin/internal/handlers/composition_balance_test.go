package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The composition card must not answer a measurement disagreement by hiding
// everything it knows.
//
// The shares come from two systems -- the access log counts requests, the event
// log counts solves and abandons -- read by separate queries a moment apart, so
// on a busy node they disagree slightly and the parts can land over the whole.
// The card used to respond by dropping the WHOLE breakdown (abandons,
// unchallenged passes, re-binds, passthrough, balance) behind one line blaming
// the counters for double counting.
//
// The diagnosis was also wrong.  Summed straight from the access-log table the
// parts equal the total exactly -- verified on the node that showed the warning,
// where the residue was 0 across repeated samples while the card read 942,209
// against a total of 941,283.  The reader lost every number they had and was
// sent after a fault that was not there.
func TestCompositionKeepsItsBreakdownWhenTheSharesDisagree(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	const site = "example.com"
	if _, err := h.DB.Exec(`CREATE TABLE unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		kind VARCHAR(32) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_min, site, kind))`); err != nil {
		t.Fatal(err)
	}
	// The log feed is behind (challenge_served has not caught up) while the
	// event log has the serves -- the shape that makes the fired count come
	// from events while every other share comes from the log.
	for k, n := range map[string]int{
		"total": 10000, "challenge_served": 0, "crawler_pass": 2000,
		"bypass_pass": 400, "pow": 100,
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES (?, '', x'7f000001', ?, '{"chmode":"pow_only"}', datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	ev("serve", 9000)
	ev("bv_pow_only", 200)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()

	// Premise: this really is the oversubscribed case.  If a later change makes
	// the shares balance here, the test should say so rather than pass by
	// covering nothing.
	if !strings.Contains(body, i18n.T(i18n.LangEN, "overview.kpi.other_head")) {
		t.Fatal("the residue breakdown is missing entirely -- the card hid what it knows")
	}
	// The named parts survive, which is the whole point.
	for _, key := range []string{
		"overview.kpi.other_unchallenged_label",
		"overview.kpi.other_skew_label",
	} {
		if want := i18n.T(i18n.LangEN, key); !strings.Contains(body, want) {
			t.Errorf("the breakdown dropped %q", want)
		}
	}
}

// The segments must not oversubscribe the total just because the event side
// reads higher than the log side.
//
// It systematically does: the log is counted in minute buckets over exactly
// 1440 of them, while the event side comes from hourly buckets bounded
// inclusively at both ends, so it carries up to a whole extra hour -- thousands
// of requests on a busy node, drifting in and out as the window slides.  The
// fired count used to switch to the event side on that comparison alone, which
// is the one term in the composition that can push the parts past the whole:
// everything else comes from a single snapshot of a single table, and the solve
// counts cancel exactly because both sides read the same variable.
//
// Seeded here with a healthy log feed and MORE serve events than the log
// recorded -- exactly the shape that produced 942,209 against a total of
// 941,283 in production.
func TestCompositionIgnoresTheEventCountWhenTheLogFeedIsHealthy(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	const site = "example.com"
	if _, err := h.DB.Exec(`CREATE TABLE unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL,
		kind VARCHAR(32) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_min, site, kind))`); err != nil {
		t.Fatal(err)
	}
	for k, n := range map[string]int{
		"total": 10000, "challenge_served": 7000, "crawler_pass": 2000,
		"bypass_pass": 400, "pow": 600,
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (strftime('%s','now')/60, ?, ?, ?)`, site, k, n); err != nil {
			t.Fatal(err)
		}
	}
	ev := func(phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, payload_json, date_created)
				VALUES (?, '', x'7f000001', ?, '{"chmode":"pow_only"}', datetime('now'))`, site, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	ev("serve", 8000) // the event side reads 1,000 higher than the log
	ev("bv_pow_only", 100)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/?site="+site, nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, req)
	body := rr.Body.String()

	// Blocked follows the log (7,000 fired minus the 100 that solved), not the
	// 8,000 the event log happened to hold.
	if !strings.Contains(body, legendEntry("overview.kpi.nonhuman_bad", "6,900")) {
		m := legendPattern("overview.kpi.nonhuman_bad").FindString(body)
		t.Errorf("blocked reads %q, want 6,900: the event count overrode a healthy log feed", m)
	}
	// And the shares stay inside the total, so the residue keeps its meaning.
	if strings.Contains(body, i18n.T(i18n.LangEN, "overview.kpi.other_unknown")) {
		t.Error("the card reports the segments oversubscribing the total on a consistent snapshot")
	}
}
