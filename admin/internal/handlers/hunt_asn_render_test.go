package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// The ASN ranking card renders end to end, and each row offers the one action
// that matters: a link into the ASN tab with the network already filled in.
//
// The card is also the reason the geo override exists in a handler test -- the
// ranking is skipped entirely without an ASN mmdb, so without seeding one this
// would pass by rendering nothing.
func TestHuntASNRankingRenders(t *testing.T) {
	h := newTestHandler(t)
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.7:US:398781,203.0.113.8:US:398781")
	h.IPGeo = ipgeo.Open("", "")
	if !h.IPGeo.ASNLoaded() {
		t.Fatal("test geo override did not enable ASN lookups")
	}
	for _, ip := range []string{"x'CB007107'", "x'CB007108'"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (ip_address, host, phase, date_created) ` +
				`VALUES (` + ip + `, 'example.com', 'serve', datetime('now'))`,
		); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	for _, want := range []string{
		`class="rank-card rank-card-asn"`, // the card itself
		"AS398781",                        // the resolved network
		// Registers from the ranking rather than navigating to the ASN tab:
		// leaving the page drops the range, the filters and the fold state.
		`class="js-asn-form"`,
		`name="asn" value="398781"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hunt page is missing %q", want)
		}
	}
}

// Without an ASN mmdb the card is omitted rather than rendered empty: an empty
// "top networks" table reads as "no networks were seen", which is a different
// and false claim from "this install cannot resolve networks".
func TestHuntASNRankingOmittedWithoutMMDB(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_event (ip_address, host, phase, date_created) ` +
			`VALUES (x'7f000001', 'example.com', 'serve', datetime('now'))`,
	); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `class="rank-card rank-card-asn"`) {
		t.Fatal("ASN card must be omitted when no ASN mmdb is loaded")
	}
}
