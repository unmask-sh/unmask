package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Changing the period keeps the filters: the preset range links and the
// custom-range form carry whatever the log is narrowed to.  They used to
// carry only the range, so a filtered hunt lost its filters the moment the
// operator looked at a different period.  The reset link stays bare -- it
// is the one that clears them.
func TestHuntRangeLinksKeepFilters(t *testing.T) {
	h := newTestHandler(t)
	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", path, rr.Code)
		}
		return rr.Body.String()
	}

	body := get("/unmask/admin/hunt/?range=24h&ua=python+requests&phase=bv_pow_only&n=200&force_reason=&offset=50")
	for _, want := range []string{
		// html/template writes & as &amp; in an attribute.
		`href="?range=1h&amp;ua=python%20requests&amp;phase=bv_pow_only&amp;n=200"`,
		`href="?range=6h&amp;ua=python%20requests&amp;phase=bv_pow_only&amp;n=200"`,
		`href="?range=24h&amp;ua=python%20requests&amp;phase=bv_pow_only&amp;n=200"`,
		// The custom-range form carries them as hidden fields.
		`<input type="hidden" name="ua" value="python requests">`,
		`<input type="hidden" name="phase" value="bv_pow_only">`,
		`<input type="hidden" name="n" value="200">`,
		// Clearing the filters is still one link away.
		`href="?range=24h" class="rank-act reset"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered hunt page lacks %q", want)
		}
	}
	// A position in the log (the page offset) is not a filter.
	if strings.Contains(body, "offset=50") {
		t.Error("the range links carry the page offset")
	}

	// Nothing narrowed, nothing carried.
	body = get("/unmask/admin/hunt/")
	for _, want := range []string{`href="?range=1h"`, `href="?range=6h"`, `href="?range=24h"`} {
		if !strings.Contains(body, want) {
			t.Errorf("plain hunt page lacks %q", want)
		}
	}
	if strings.Contains(body, `type="hidden" name="ua"`) {
		t.Error("the custom-range form carries a filter that is not active")
	}
}
