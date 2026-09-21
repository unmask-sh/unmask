package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// feedRoundTripper: stub http.RoundTripper that answers every request with a
// canned community-bans feed and counts how many times it was hit.
type feedRoundTripper struct {
	body string
	hits int32
	auth atomic.Value // string: the Authorization header of the most recent request
}

func (f *feedRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&f.hits, 1)
	f.auth.Store(r.Header.Get("Authorization"))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

// newCommunityBansSaveHarness wires a Handler whose AdminSettingsSave can run
// end-to-end: a temp config.yml on disk (so the fresh-disk-read save path
// works), a writable OutputDir/MapDir (so nginxconf.Render + the pull's
// WriteMapFiles succeed), and a community-bans Client backed by a stub hub.
// subscribe_mode starts off.
func newCommunityBansSaveHarness(t *testing.T) (*Handler, *feedRoundTripper) {
	t.Helper()
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")

	s := h.snapshotSettings()
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.CommunityBans.SubscribeMode = settings.SubscribeOff
	// Seed a token so the independent post-save register goroutine (which
	// fires when subscribe goes active with an empty token) does not also hit
	// the stub hub and inflate the feed-fetch count.  The feed itself is still
	// a public GET; the token only rides along so the hub can count running
	// installs, which is what TestCommunityBansPullCarriesTheToken covers.
	s.CommunityBans.Token = "seeded-token"
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	const feed = `{"generated_at":1,"version":2,"entries":[{"match":"ip_only","ip":"203.0.113.9","reason":"test"}]}`
	rt := &feedRoundTripper{body: feed}
	h.CommunityBans = &communitybans.Client{
		UserAgent:      "unmask-test",
		SettingsGetter: h.SnapshotSettings,
		SettingsUpdate: h.UpdateSettings,
		MapDir:         dir,
		HTTPClient:     &http.Client{Transport: rt},
	}
	return h, rt
}

// postCommunityBansSave drives AdminSettingsSave for the community-bans tab with
// the given subscribe_mode and returns the recorder.
func postCommunityBansSave(t *testing.T, h *Handler, mode string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"subscribe_mode": {mode}}
	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=community-bans",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	return rr
}

// TestCommunityBansSubscribeOnTriggersPull locks the off -> on immediate pull:
// flipping subscribe_mode from off to fetch must kick an out-of-band feed pull
// so the "共有 BAN" browse list (GetCachedDoc) populates right away instead of
// waiting for the next hourly tick.
func TestCommunityBansSubscribeOnTriggersPull(t *testing.T) {
	h, rt := newCommunityBansSaveHarness(t)

	if d := h.CommunityBans.GetCachedDoc(); len(d.Entries) != 0 {
		t.Fatalf("precondition: cached doc should be empty, got %d", len(d.Entries))
	}

	rr := postCommunityBansSave(t, h, settings.SubscribeFetch)
	if rr.Code != http.StatusFound {
		t.Fatalf("save: want 302, got %d body=%s", rr.Code, rr.Body.String())
	}
	// The success path carries saved=1; a render failure would carry an err
	// flash and return before the pull is ever scheduled.
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "saved=1") {
		t.Fatalf("save did not reach the success path: Location=%q", loc)
	}

	// The pull runs in a goroutine. LastPulledAt is the last thing Pull writes
	// (after WriteMapFiles), so polling it confirms the pull fully completed.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.snapshotSettings().CommunityBans.LastPulledAt > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.snapshotSettings().CommunityBans.LastPulledAt; got == 0 {
		t.Fatal("subscribe off->on did not trigger a feed pull (LastPulledAt still 0)")
	}
	if n := atomic.LoadInt32(&rt.hits); n != 1 {
		t.Fatalf("expected exactly 1 hub fetch, got %d", n)
	}
	doc := h.CommunityBans.GetCachedDoc()
	if len(doc.Entries) != 1 || doc.Entries[0].IP != "203.0.113.9" {
		t.Fatalf("browse doc not populated by the immediate pull: %+v", doc.Entries)
	}
}

// TestCommunityBansSubscribeStaysOffNoPull is the negative: a community-bans
// save that leaves subscribe off must NOT fetch the hub (no off -> on edge).
func TestCommunityBansSubscribeStaysOffNoPull(t *testing.T) {
	h, rt := newCommunityBansSaveHarness(t)

	rr := postCommunityBansSave(t, h, settings.SubscribeOff)
	if rr.Code != http.StatusFound {
		t.Fatalf("save: want 302, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Give any (erroneously) spawned pull goroutine time to run, then assert
	// the hub was never contacted and nothing got cached / stamped.
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&rt.hits); n != 0 {
		t.Fatalf("off->off save must not fetch the hub, got %d fetches", n)
	}
	if got := h.snapshotSettings().CommunityBans.LastPulledAt; got != 0 {
		t.Fatalf("off->off save must not pull (LastPulledAt=%d)", got)
	}
	if d := h.CommunityBans.GetCachedDoc(); len(d.Entries) != 0 {
		t.Fatalf("off->off save must not populate the browse doc, got %d entries", len(d.Entries))
	}
}

// lastAuth: the Authorization header the stub hub saw, "" when there was none.
func (f *feedRoundTripper) lastAuth() string {
	v, _ := f.auth.Load().(string)
	return v
}

// The pull identifies the install so the hub can count deployments that are
// actually running -- without it last_seen_at only moves at register and at
// submit, and a subscriber of many months is indistinguishable from a
// registration thrown away at once.  It is the operator's call, so the two
// states both need locking down: sending it when asked, and sending nothing
// at all when not.  The feed comes back the same either way.
func TestCommunityBansPullCarriesTheToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		liveness bool
		token    string
		want     string
	}{
		{"opted in", true, "seeded-token", "Bearer seeded-token"},
		{"opted out", false, "seeded-token", ""},
		{"no token yet", true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, rt := newCommunityBansSaveHarness(t)
			h.updateSettingsInMemory(func(s *settings.Settings) {
				s.CommunityBans.PublishLiveness = tc.liveness
				s.CommunityBans.Token = tc.token
				s.CommunityBans.SubscribeMode = settings.SubscribeFetch
			})
			if _, err := h.CommunityBans.Pull(t.Context()); err != nil {
				t.Fatalf("pull: %v", err)
			}
			if got := rt.lastAuth(); got != tc.want {
				t.Errorf("Authorization header %q, want %q", got, tc.want)
			}
			// Whatever the choice, the feed still arrives.
			if d := h.CommunityBans.GetCachedDoc(); len(d.Entries) != 1 {
				t.Errorf("feed not applied: %d entries, want 1", len(d.Entries))
			}
		})
	}
}
