package nginxconf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

func relayDoc(t *testing.T, gen string) []byte {
	t.Helper()
	b, err := json.Marshal(relay.Doc{SchemaVersion: 1, GeneratedAt: gen, Relays: map[string]relay.Entry{
		"apple-private-relay": {Countries: map[string][]string{"JP": {"172.224.226.0/27"}, "GB": {"172.224.226.32/31"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// relayHub serves the relay list (and its .sig) under /feed/, a 500 for the
// bypass-IP document beside it, and 304 to a conditional request.
func relayHub(t *testing.T, body []byte, sig string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feed/" + relay.FileName:
			if r.Header.Get("If-Modified-Since") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", "Mon, 13 Oct 2026 06:17:00 GMT")
			_, _ = w.Write(body)
		case "/feed/" + relay.FileName + FeedSigSuffix:
			if sig == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sig + "\n"))
		default:
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
}

// TestRelayPull: the relay list comes from beside the hub document, held to
// its signature rule (required from the published hub), and goes in even
// when the bypass-IP document failed; a conditional re-pull is a no-op, a
// bad or missing signature installs nothing.
func TestRelayPull(t *testing.T) {
	priv, restore := testFeedKey(t)
	defer restore()
	defer relay.Set(nil)
	body := relayDoc(t, "2026-10-13T06:17:00Z")

	for _, c := range []struct {
		name, sig, want string
	}{
		{"bad signature", SignFeed(priv, []byte("other bytes")), "feed signature"},
		{"no signature from the published hub", "", "signature required"},
	} {
		relay.Set(nil)
		srv := relayHub(t, body, c.sig)
		saved := publishedHubURL
		publishedHubURL = srv.URL + "/feed/bypass-iprange-all.json"
		s := &Sync{Dir: t.TempDir(), PullRelay: true}
		_ = s.PullOnce(context.Background())
		publishedHubURL = saved
		srv.Close()
		if relay.Current() != nil {
			t.Errorf("%s: a list was installed", c.name)
		}
		if _, err := os.Stat(filepath.Join(s.Dir, relay.FileName)); !os.IsNotExist(err) {
			t.Errorf("%s: a list was written", c.name)
		}
	}

	relay.Set(nil)
	srv := relayHub(t, body, SignFeed(priv, body))
	defer srv.Close()
	saved := publishedHubURL
	publishedHubURL = srv.URL + "/feed/bypass-iprange-all.json"
	defer func() { publishedHubURL = saved }()
	renders := 0
	s := &Sync{Dir: t.TempDir(), PullRelay: true, RenderFunc: func() error { renders++; return nil }}
	if err := s.PullOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("the bypass-IP document's failure should be what PullOnce reports, got %v", err)
	}
	if tb := relay.Current(); tb == nil || tb.Prefixes != 2 || renders != 1 {
		t.Fatalf("the relay list did not go in beside a failed bypass-IP pull: %+v, renders %d", tb, renders)
	}
	if b, err := os.ReadFile(filepath.Join(s.Dir, relay.FileName)); err != nil || string(b) != string(body) {
		t.Errorf("the list kept on disk: %v", err)
	}
	// Unchanged on the hub: 304, nothing re-rendered.
	if got, err := s.pullRelay(context.Background()); got || err != nil {
		t.Errorf("a conditional re-pull: installed %v, err %v", got, err)
	}

	// A hub of the operator's own without the list: logged, list in use stays.
	own := httptest.NewServer(http.NotFoundHandler())
	defer own.Close()
	s2 := &Sync{Dir: t.TempDir(), HubURL: own.URL + "/x/bypass-iprange-all.json", PullRelay: true}
	if got, err := s2.pullRelay(context.Background()); got || err == nil || !strings.Contains(err.Error(), "not on this hub") {
		t.Errorf("own hub without the list: installed %v, err %v", got, err)
	}
	if relay.Current() == nil {
		t.Error("a 404 cleared the list in use")
	}
}
