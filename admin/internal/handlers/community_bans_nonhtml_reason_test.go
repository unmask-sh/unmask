package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A client the shared feed caught that cannot take the HTML page (no
// text/html in Accept: a script, a crawler asking for JSON) is recorded as a
// feed hit, force_reason=community_bans, as the HTML page's visitor is, and
// is told that reason.  Before, the JSON answer mirrored nginx's headers only,
// and native nginx sends none for a feed hit, so the serve was recorded as
// force_reason=none and the Community Bans tab, which counts feed hits by
// their name, missed it.  The matcher is built through the pull, the map
// files and the loader -- the path production takes.
func TestNonHTMLServeNamesAFeedHit(t *testing.T) {
	h, rt := newCommunityBansSaveHarness(t)
	s := h.snapshotSettings()
	s.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	// On disk as well: the pull records its time through the settings
	// update, which re-reads the file.
	if err := settings.Save(s, h.ConfigPath); err != nil {
		t.Fatalf("save config: %v", err)
	}
	h.SetSettings(s)
	const listed, unlisted = "203.0.113.9", "203.0.113.10"
	rt.body = `{"generated_at":1,"version":2,"entries":[{"match":"ip_only","ip":"` + listed + `","reason":"test","promoted":true}]}`
	if _, err := h.CommunityBans.Pull(context.Background()); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if _, ok := h.CommunityBans.Matcher().Hit(listed, ""); !ok {
		t.Fatal("the pull did not load the listed address into the matcher")
	}

	serve := func(ip string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, req)
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("the non-HTML answer is not JSON: %v (%s)", err, rr.Body.String())
		}
		return rr.Code, body
	}
	recorded := func(ip string) map[string]any {
		t.Helper()
		var payload map[string]any
		waitFor(t, "the serve event of "+ip, 3*time.Second, func() bool {
			var raw string
			err := h.DB.QueryRowContext(context.Background(),
				`SELECT COALESCE(payload_json, '') FROM unmask_event
				  WHERE phase = 'serve' AND ip_address = ? ORDER BY id DESC LIMIT 1`, events.PackIP(ip)).Scan(&raw)
			if err != nil || raw == "" {
				return false
			}
			payload = nil
			return json.Unmarshal([]byte(raw), &payload) == nil
		})
		return payload
	}

	code, body := serve(listed)
	if code != http.StatusForbidden || body["reason"] != "community_bans" {
		t.Fatalf("listed client: status %d, body %v; want 403 and reason community_bans", code, body)
	}
	if p := recorded(listed); p["force_reason"] != "community_bans" || p["non_html_client"] != float64(1) {
		t.Errorf("listed client's serve recorded as %v; want force_reason community_bans, non_html_client 1", p)
	}

	code, body = serve(unlisted)
	if code != http.StatusForbidden || body["reason"] != "none" {
		t.Fatalf("unlisted client: status %d, body %v; want 403 and reason none", code, body)
	}
	if p := recorded(unlisted); p["force_reason"] != "none" {
		t.Errorf("unlisted client's serve recorded as %v; want force_reason none", p)
	}
}
