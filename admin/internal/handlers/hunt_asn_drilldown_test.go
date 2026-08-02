package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// Every other rank card lets the operator click a request count and see the
// requests behind it.  The network card did not, because the ASN is resolved
// from the mmdb at render time and does not exist on the event row -- so the
// drill-down has to work out which addresses belong to the network and filter
// on those.
func TestHuntASNDrillDownFiltersToThatNetworksRequests(t *testing.T) {
	h := newTestHandler(t)
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.7:US:64500,203.0.113.8:US:64500,198.51.100.9:US:64501")
	h.IPGeo = ipgeo.Open("", "")
	if !h.IPGeo.ASNLoaded() {
		t.Fatal("test geo override did not enable ASN lookups")
	}
	// Two addresses in AS64500, one in a different network.
	for _, ip := range []string{"x'CB007107'", "x'CB007108'", "x'C6336409'"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (ip_address, host, phase, date_created) ` +
				`VALUES (` + ip + `, 'example.com', 'serve', datetime('now'))`); err != nil {
			t.Fatal(err)
		}
	}

	get := func(url string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, httptest.NewRequest(http.MethodGet, url, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", url, rr.Code)
		}
		return rr.Body.String()
	}

	// The card offers the drill-down at all.
	if !strings.Contains(get("/unmask/admin/hunt/"), "asn=64500") {
		t.Error("the network card's request count is not a link into the log")
	}

	body := get("/unmask/admin/hunt/?asn=64500")
	ips := regexp.MustCompile(`data-ip="([^"]+)"`).FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	for _, m := range ips {
		seen[m[1]] = true
	}
	if !seen["203.0.113.7"] || !seen["203.0.113.8"] {
		t.Errorf("the drill-down dropped addresses that belong to the network: %v", seen)
	}
	if seen["198.51.100.9"] {
		t.Errorf("the drill-down shows an address from another network: %v", seen)
	}
	// The filter has to survive a range change or a row-count change, which go
	// through the form -- it has no text input of its own to be typed back in.
	if !strings.Contains(body, `name="asn" value="64500"`) {
		t.Error("the network filter is not carried through the filter form")
	}
	// And it has to be visible and clearable, like every other active filter.
	if !strings.Contains(body, "asn-filter-chip") {
		t.Error("an active network filter is not shown anywhere on the page")
	}
}

// An install with no ASN database cannot say which addresses belong to a
// network.  Returning the unfiltered log would read as that network accounting
// for every request on the page.
func TestHuntASNDrillDownShowsNothingWithoutMMDB(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_event (ip_address, host, phase, date_created) ` +
			`VALUES (x'7f000001', 'example.com', 'serve', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?asn=64500", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `data-ip="127.0.0.1"`) {
		t.Error("without an ASN database the drill-down returns the whole log as if it were one network")
	}
}

// The network ranking leads with the organisation, not the AS number: almost
// nobody reads "AS55286", everybody reads "B2 Net Solutions".  The number is
// still on the row for whoever wants it, and it is what shows when the database
// cannot name the network -- which is then all there is to show.
func TestNetworkRankingLeadsWithTheOrganisation(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	card := tpl[strings.Index(tpl, `rank-card rank-card-asn`):]
	card = card[:strings.Index(card, "</table>")]

	key := regexp.MustCompile(`(?s)<td class="key".*?</td>`).FindString(card)
	if key == "" {
		t.Fatal("could not find the network cell")
	}
	if !strings.Contains(key, `{{ if .Org }}{{ .Org }}`) {
		t.Error("the network cell no longer leads with the organisation name")
	}
	if !strings.Contains(key, `{{ else if .ASN }}<strong>AS{{ .ASN }}</strong>`) {
		t.Error("a network the database cannot name has nothing to fall back to")
	}
	if !strings.Contains(key, `title="AS{{ .ASN }}"`) {
		t.Error("the AS number is no longer recoverable from the row")
	}
	// The active-filter chip is read away from the ranking, so it has to name
	// the network too -- a bare number there says nothing about what was filtered.
	if !strings.Contains(tpl, `{{ if .ASNFilterOrg }}{{ .ASNFilterOrg }}`) {
		t.Error("the active network filter shows only a number")
	}
}
