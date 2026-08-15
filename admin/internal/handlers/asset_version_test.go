package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The shared static assets are cache-busted by the build they belong to.
//
// popover-pin.css / .js are served with max-age caching and were linked bare,
// so a binary swap left every browser pairing the NEW page HTML with the
// PREVIOUS build's JS and CSS for up to an hour.  That is how a deployed fix
// can fail in front of the person who just reloaded: the underline lived in
// the cached-out CSS, the hover-grace in the cached-out JS, and the page
// showed neither while the e2e suite -- a fresh browser with an empty cache --
// stayed green.
func TestSharedAssetsCarryTheBuildStamp(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)

	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()

	stamp := fmt.Sprintf("?v=%d", buildVersionStamp)
	for _, asset := range []string{"popover-pin.css", "popover-pin.js"} {
		if !strings.Contains(body, asset+stamp) {
			t.Errorf("%s is linked without the build stamp -- a binary swap leaves browsers on the previous build's copy", asset)
		}
		if strings.Contains(body, asset+`"`) {
			t.Errorf("%s still has a bare (unversioned) link", asset)
		}
	}
}
