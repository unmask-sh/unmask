package handlers

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// An abandon is marked as "got in afterwards" only when the address actually
// obtained a pass.
//
// The old test was "did anything else arrive from this address", which a bot
// satisfies by being challenged again.  Observed on tool1-us: one client, two
// sessions three seconds apart --
//
//	02:50:41.742 serve   (session A)
//	02:50:42.009 captcha
//	02:50:44.146 serve   (session B)
//	02:50:44.267 abandon (session A)  <- "they stayed on the site"
//	02:50:44.978 abandon (session B)
//
// -- and it never once got in.  The abandon that mattered was reported as the
// reassuring outcome, on the client type that abandons most.
func TestAbandonPassedAfterRequiresAPass(t *testing.T) {
	h := newTestHandler(t)

	// (a) The production shape: abandon, then another challenge served to the
	// same address seconds later, and another abandon.  No pass anywhere.
	seed := func(ip, phase, at string) {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,`+ip+`,'UA','','',0,?,0,0,'','','{}',?)`, phase, at); err != nil {
			t.Fatalf("seed %s: %v", phase, err)
		}
	}
	const looper = `x'0a000001'` // 10.0.0.1
	seed(looper, "serve", "2026-08-15 02:50:41.742")
	seed(looper, "abandon", "2026-08-15 02:50:44.267")
	seed(looper, "serve", "2026-08-15 02:50:44.146")
	seed(looper, "abandon", "2026-08-15 02:50:44.978")

	// (b) A client that left one attempt and passed on the next.
	const enterer = `x'0a000002'` // 10.0.0.2
	seed(enterer, "abandon", "2026-08-15 02:50:41.000")
	seed(enterer, "serve", "2026-08-15 02:50:43.000")
	seed(enterer, "bv_pow_only", "2026-08-15 02:50:50.000")

	// (c) A rebind rejection is a refusal, not entry.
	const rejected = `x'0a000003'` // 10.0.0.3
	seed(rejected, "abandon", "2026-08-15 02:50:41.000")
	seed(rejected, "bv_rebind_reject", "2026-08-15 02:50:45.000")

	// FetchPaged, not FetchSince: only the paged path fills PassedAfter, and it
	// is the path the hunt page uses.  sinceMin is large enough to cover the
	// seeded timestamps regardless of when the test runs.
	rows, err := events.FetchPaged(context.Background(), h.DB,
		"", "", "", "", "", "", "", nil, 60*24*365*10, 200, 0)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	got := map[string]int{}
	for _, r := range rows {
		if r.Phase == "abandon" {
			got[r.IP] += r.PassedAfter
		}
	}
	if got["10.0.0.1"] != 0 {
		t.Errorf("a client that was merely challenged again counts as having got in (%d)", got["10.0.0.1"])
	}
	if got["10.0.0.2"] == 0 {
		t.Error("a client that abandoned and then passed is not credited with getting in")
	}
	if got["10.0.0.3"] != 0 {
		t.Errorf("a rejected rebind counts as entry (%d)", got["10.0.0.3"])
	}
}
