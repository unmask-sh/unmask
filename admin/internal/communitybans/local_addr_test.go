package communitybans

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The addresses no visitor comes from, and two that visitors do.
var (
	localAddrs  = []string{"127.0.0.1", "::1", "10.0.0.1", "172.17.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "::", "224.0.0.1", "fe80::1", "fc00::1", "ff02::1", "::ffff:10.0.0.1"}
	publicAddrs = []string{"203.0.113.9", "2001:db8::42", "::ffff:203.0.113.9"}
)

func TestPublicAddr(t *testing.T) {
	for _, a := range localAddrs {
		if publicAddr(a) {
			t.Errorf("publicAddr(%q) = true", a)
		}
	}
	for _, a := range publicAddrs {
		if !publicAddr(a) {
			t.Errorf("publicAddr(%q) = false", a)
		}
	}
	for _, a := range []string{"", "default", "203.0.113.0/24"} {
		if publicAddr(a) {
			t.Errorf("publicAddr(%q) = true: not an address", a)
		}
	}
}

// nginx matches the shared-ban maps on the address it sees the connection
// from.  Behind a proxy with no real-IP set up that is the proxy's inside
// address, for every request: a promoted entry on 127.0.0.1 or 10.0.0.1
// challenged every visitor of every such install.  The guard holds such an
// entry back, with its own reason, whichever way it is matched; and the map
// writer drops one handed to it directly.
func TestGuardNeverAppliesAnAddressNoVisitorComesFrom(t *testing.T) {
	now := time.Now()
	var entries []FeedEntry
	for _, a := range localAddrs {
		entries = append(entries, FeedEntry{Match: MatchIPOnly, IP: a, Promoted: true})
	}
	entries = append(entries,
		FeedEntry{Match: MatchIPJA4, IP: "10.0.0.2", JA4: botJA4, Promoted: true},
		FeedEntry{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true},
		FeedEntry{Match: MatchIPJA4, IP: "2001:db8::42", JA4: botJA4, Promoted: true},
		FeedEntry{Match: MatchIPOnly, IP: "192.168.7.7"}, // not promoted: untouched
	)
	st := newGuardState()
	observePromoted(entries, st, now)
	kept, held, p := guardEntries(entries, st, now)
	if got, want := strings.Join(keysOf(kept), " "), "ip_ja4:2001:db8::42|"+botJA4+" ip_only:192.168.7.7 ip_only:203.0.113.9"; got != want {
		t.Errorf("kept = %q, want %q", got, want)
	}
	if p.Local != len(localAddrs)+1 || p.Total() != p.Local {
		t.Errorf("pending = %+v, want %d local", p, len(localAddrs)+1)
	}
	for _, a := range localAddrs {
		if held["ip_only:"+a] != PendingLocal {
			t.Errorf("%s is held as %q, want %q", a, held["ip_only:"+a], PendingLocal)
		}
	}
	if _, ok := st.Applied["ip_only:127.0.0.1"]; ok {
		t.Error("a held entry is on the applied list")
	}

	// The writer alone, handed the same entries.
	dir := t.TempDir()
	if err := WriteMapFiles(FeedDocument{Version: 2, Entries: entries}, dir); err != nil {
		t.Fatal(err)
	}
	ipMap, err := os.ReadFile(filepath.Join(dir, MapFileIP))
	if err != nil {
		t.Fatal(err)
	}
	ipja4Map, err := os.ReadFile(filepath.Join(dir, MapFileIPJA4))
	if err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, line := range strings.Split(string(ipMap)+string(ipja4Map), "\n") {
		if strings.HasPrefix(line, `"`) {
			keys++
		}
	}
	if keys != 2 || !strings.Contains(string(ipMap), `"203.0.113.9" 1;`) || !strings.Contains(string(ipja4Map), `"2001:db8::42:`+botJA4+`" 1;`) {
		t.Errorf("the map files hold %d keys, want the two public entries:\n%s%s", keys, ipMap, ipja4Map)
	}
}

// Through Pull, as the daemon runs it: the inside addresses reach neither
// the map file nor the forward-auth matcher, and the page is told why.
func TestPullKeepsInsideAddressesOutOfTheMaps(t *testing.T) {
	dir := t.TempDir()
	doc := FeedDocument{GeneratedAt: time.Now().Unix(), Version: 2, Entries: []FeedEntry{
		{Match: MatchIPOnly, IP: "127.0.0.1", Promoted: true},
		{Match: MatchIPOnly, IP: "::1", Promoted: true},
		{Match: MatchIPOnly, IP: "172.17.0.1", Promoted: true},
		{Match: MatchIPOnly, IP: "10.0.0.1", Promoted: true},
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	var cur settings.Settings
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	cur.CommunityBans.FeedURL = srv.URL
	c := &Client{
		UserAgent:      "unmask-test",
		SettingsGetter: func() settings.Settings { return cur },
		SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
		MapDir:         dir,
	}
	if _, err := c.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	m, err := os.ReadFile(filepath.Join(dir, MapFileIP))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"127.0.0.1", "::1", "172.17.0.1", "10.0.0.1"} {
		if strings.Contains(string(m), `"`+a+`"`) {
			t.Errorf("%s is in the map file:\n%s", a, m)
		}
		if _, hit := c.Matcher().Hit(a, ""); hit {
			t.Errorf("the matcher enforces %s", a)
		}
		if c.PendingKinds()["ip_only:"+a] != PendingLocal {
			t.Errorf("%s is not listed as held for being local: %v", a, c.PendingKinds())
		}
	}
	if !strings.Contains(string(m), `"203.0.113.9" 1;`) {
		t.Errorf("the public address is not in the map file:\n%s", m)
	}
	if p := c.Pending(); p.Local != 4 || p.Total() != 4 {
		t.Errorf("pending = %+v, want 4 local", p)
	}
}
