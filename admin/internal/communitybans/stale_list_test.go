package communitybans

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A shared-ban list that no pull has confirmed for a month is not enforced.
// An entry leaves the files at its own expiry when this release applied it
// (TestSharedBansExpireWhileTheHubIsDown); what an earlier daemon wrote has
// no expiry on record, and an entry the hub gave none never had one: both
// stayed in force for as long as the hub was out of reach, however long.
func TestSharedListNobodyConfirmedForAMonthIsNotEnforced(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now()
	day := int64(86400)
	doc := FeedDocument{GeneratedAt: t0.Unix(), Version: 2, Entries: []FeedEntry{
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true, ExpiresAt: t0.Unix() + 100*day}, // a hub that keeps entries long
		{Match: MatchIPOnly, IP: "203.0.113.11", Promoted: true},                                // no expiry at all
		{Match: MatchIPJA4, IP: "203.0.113.10", JA4: botJA4b, Promoted: true, ExpiresAt: t0.Unix() + 100*day},
	}}
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "the hub is away", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	var cur settings.Settings
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	cur.CommunityBans.FeedURL = srv.URL + "/api/feed/list.json"
	cur.CommunityBans.RegisterURL = srv.URL + "/api/feed/register"
	cur.CommunityBans.Token = "registered-once"
	cur.CommunityBans.HN = "swift-otter-a3f7"
	clock := t0
	var logged bytes.Buffer
	newClient := func() *Client {
		return &Client{
			UserAgent:      "unmask-test",
			SettingsGetter: func() settings.Settings { return cur },
			SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
			MapDir:         dir,
			Logger:         log.New(&logged, "", 0),
			now:            func() time.Time { return clock },
		}
	}
	c := newClient()
	ctx := t.Context()
	held := func() int {
		t.Helper()
		n := 0
		for _, f := range []string{MapFileIP, MapFileIPJA4, MapFileJA4} {
			set := map[string]struct{}{}
			if err := loadMapKeys(filepath.Join(dir, f), set); err != nil {
				t.Fatal(err)
			}
			n += len(set)
		}
		return n
	}
	hit := func(c *Client, ip, ja4 string) bool { _, ok := c.Matcher().Hit(ip, ja4); return ok }
	failedPull := func(c *Client) {
		t.Helper()
		if _, err := c.Pull(ctx); err == nil {
			t.Fatal("the pull succeeded against a hub that answers 502")
		}
	}

	if _, err := c.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if held() != 3 || cur.CommunityBans.LastPulledAt == 0 {
		t.Fatalf("after the pull: %d keys in the files, last pull %d", held(), cur.CommunityBans.LastPulledAt)
	}

	// The hub goes away.  Twenty-nine days on the list is still the last
	// word the install had, and is enforced.
	down.Store(true)
	clock = t0.Add(29 * 24 * time.Hour)
	failedPull(c)
	if held() != 3 || !hit(c, "203.0.113.11", "") {
		t.Fatalf("29 days without the hub: %d keys in the files, want all 3", held())
	}
	// Thirty-one days on it is not: the files are empty, the matcher too,
	// and nothing counts as applied.
	clock = t0.Add(31 * 24 * time.Hour)
	failedPull(c)
	if held() != 0 || hit(c, "203.0.113.9", "") || hit(c, "203.0.113.11", "") || hit(c, "203.0.113.10", botJA4b) {
		t.Errorf("31 days without the hub: %d keys in the files, want none", held())
	}
	statePath := filepath.Join(dir, "community-bans-state.json")
	if st, err := loadGuardState(statePath); err != nil || len(st.Applied) != 0 || len(st.Enforced) != 0 {
		t.Errorf("31 days without the hub: the state still names %d applied and %d expiring entries (err %v)", len(st.Applied), len(st.Enforced), err)
	}
	if !strings.Contains(logged.String(), "no pull has reached the hub for 31 days") || !strings.Contains(logged.String(), "the 3 shared ban(s)") {
		t.Errorf("the log does not say what was done:\n%s", logged.String())
	}
	// Said once: the next failed pulls find the files empty.
	logged.Reset()
	failedPull(c)
	failedPull(newClient())
	if strings.Contains(logged.String(), "no longer enforced") {
		t.Errorf("the emptying is said again on every pull:\n%s", logged.String())
	}
	// The files are still there for nginx to include.
	for _, f := range []string{MapFileIP, MapFileIPJA4, MapFileJA4} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s is gone: nginx's include would fail: %v", f, err)
		}
	}

	// The hub is back: its list is applied again.
	down.Store(false)
	clock = time.Now()
	if _, err := c.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if held() != 3 {
		t.Errorf("the hub is back: %d keys in the files, want 3", held())
	}
}

// The files of an install whose pulls stopped under an earlier release: keys
// alone, a state that names no expiry, a last pull months back.  And the
// cases that are left alone: a last pull inside the month, and no record of
// one at all.
func TestSharedListFromAnEarlierDaemon(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name     string
		lastPull int64
		want     int // keys left in the files after a failed pull
	}{
		{"last pull five months ago", now.Add(-150 * 24 * time.Hour).Unix(), 0},
		{"last pull 31 days ago", now.Add(-31 * 24 * time.Hour).Unix(), 0},
		{"last pull ten days ago", now.Add(-10 * 24 * time.Hour).Unix(), 2},
		{"no record of a pull", 0, 2},
		{"a last pull dated ahead of the clock", now.Add(48 * time.Hour).Unix(), 2},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, MapFileIP), []byte("\"203.0.113.9\" 1;\n\"203.0.113.11\" 1;\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The state as a daemon from before this release left it: what was
		// applied and when, no expiry.
		if err := os.WriteFile(filepath.Join(dir, "community-bans-state.json"),
			[]byte(`{"applied":{"ip_only:203.0.113.9":1750000000,"ip_only:203.0.113.11":1750000000}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "the hub is away", http.StatusBadGateway)
		}))
		var cur settings.Settings
		cur.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
		cur.CommunityBans.FeedURL = srv.URL + "/api/feed/list.json"
		cur.CommunityBans.RegisterURL = srv.URL + "/api/feed/register"
		cur.CommunityBans.Token = "registered-once"
		cur.CommunityBans.HN = "swift-otter-a3f7"
		cur.CommunityBans.LastPulledAt = c.lastPull
		cl := &Client{
			UserAgent:      "unmask-test",
			SettingsGetter: func() settings.Settings { return cur },
			SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
			MapDir:         dir,
		}
		if _, err := cl.Pull(t.Context()); err == nil {
			t.Fatalf("%s: the pull succeeded against a hub that answers 502", c.name)
		}
		srv.Close()
		set := map[string]struct{}{}
		if err := loadMapKeys(filepath.Join(dir, MapFileIP), set); err != nil {
			t.Fatal(err)
		}
		if len(set) != c.want {
			t.Errorf("%s: %d keys left in the address map, want %d", c.name, len(set), c.want)
		}
		// The daemon's own matcher reads the files at its start; what it
		// answers is what they hold.
		cl.reloadMatcher(dir)
		if _, ok := cl.Matcher().Hit("203.0.113.9", ""); ok != (c.want > 0) {
			t.Errorf("%s: the matcher says %v for a listed address", c.name, ok)
		}
	}
}

// With the feed listed but not applied, or off, there is nothing to empty.
func TestStaleListLeavesAnInstallThatAppliesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, MapFileIP), []byte("\"203.0.113.9\" 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cur settings.Settings
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetch
	cur.CommunityBans.LastPulledAt = time.Now().Add(-90 * 24 * time.Hour).Unix()
	c := &Client{SettingsGetter: func() settings.Settings { return cur }, MapDir: dir}
	if n := c.dropExpired(cur, time.Now()); n != 0 {
		t.Errorf("dropExpired took out %d keys with the list not applied", n)
	}
	set := map[string]struct{}{}
	if err := loadMapKeys(filepath.Join(dir, MapFileIP), set); err != nil || len(set) != 1 {
		t.Errorf("the file was touched: %d keys (err %v)", len(set), err)
	}
}
