package handlers

import (
	"net/http/httptest"
	"testing"
)

// A render for the settings outline is marked, and only that one: the
// page-only reads (the retention tab's size of the data, the sites tab's
// hosts) are skipped on the marked render.
func TestSettingsOutlineRenderIsMarkedLite(t *testing.T) {
	r := httptest.NewRequest("GET", "/unmask/admin/settings/retention/", nil)
	if settingsOutlineLite(r) {
		t.Fatal("a page's own request is taken for the outline's")
	}
	if !settingsOutlineLite(r.WithContext(withOutlineLite(r.Context()))) {
		t.Fatal("the outline's mark is not read")
	}
}
