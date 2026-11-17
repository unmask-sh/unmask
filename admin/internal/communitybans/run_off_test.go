package communitybans

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// With submitting and subscribing both switched off the daemon says nothing
// to the hub.  It still made one request at every start: an install that had
// registered once and then left kept a token with no handle name beside it,
// and the handle-name backfill ran whatever the switches said.  Switched on,
// the backfill runs as before.
func TestStartSaysNothingToTheHubWhileSwitchedOff(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/feed/me/rederive":
			_, _ = w.Write([]byte(`{"hn":"swift-otter-a3f7","hn_derived":"swift-otter-a3f7"}`))
		default:
			_, _ = w.Write([]byte(`{"generated_at":1,"version":2,"entries":[]}`))
		}
	}))
	defer srv.Close()
	asked := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
	var cur settings.Settings
	cur.CommunityBans.Token = "registered-once"
	cur.CommunityBans.RegisterURL = srv.URL + "/api/feed/register"
	cur.CommunityBans.FeedURL = srv.URL + "/api/feed/list.json"
	c := &Client{
		UserAgent:      "unmask-test",
		SettingsGetter: func() settings.Settings { return cur },
		SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
		MapDir:         t.TempDir(),
	}

	c.start(t.Context())
	if got := asked(); len(got) != 0 {
		t.Fatalf("both switches off: the hub was asked %v", got)
	}
	if cur.CommunityBans.HN != "" {
		t.Errorf("both switches off: a handle name was fetched (%q)", cur.CommunityBans.HN)
	}

	cur.CommunityBans.SubscribeMode = settings.SubscribeFetch
	c.start(t.Context())
	got := asked()
	backfilled := false
	for _, p := range got {
		backfilled = backfilled || p == "POST /api/feed/me/rederive"
	}
	if !backfilled || cur.CommunityBans.HN != "swift-otter-a3f7" {
		t.Errorf("subscribing: the handle name was not fetched (asked %v, hn %q)", got, cur.CommunityBans.HN)
	}
}
