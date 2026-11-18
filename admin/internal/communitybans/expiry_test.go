package communitybans

import (
	"encoding/json"
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

// A shared ban leaves the map files at its own expiry whether or not the
// hub can be reached.  The expiry was looked at only when the files were
// written, which a pull that reached the hub does: with the hub out of
// reach every entry of the last good pull stayed in force for as long as
// that lasted, the ones due to lapse within the hour among them.
func TestSharedBansExpireWhileTheHubIsDown(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now()
	hour := int64(3600)
	doc := FeedDocument{GeneratedAt: t0.Unix(), Version: 2, Entries: []FeedEntry{
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true, ExpiresAt: t0.Unix() + 1*hour},
		{Match: MatchIPJA4, IP: "203.0.113.10", JA4: botJA4b, Promoted: true, ExpiresAt: t0.Unix() + 3*hour},
		{Match: MatchIPOnly, IP: "203.0.113.11", Promoted: true},                            // no expiry: stays
		{Match: MatchIPOnly, IP: "203.0.113.12", ExpiresAt: t0.Unix() + 1*hour},             // listed, not promoted: never written
		{Match: MatchIPOnly, IP: "10.0.0.5", Promoted: true, ExpiresAt: t0.Unix() + 1*hour}, // no visitor's address: held back
		{Match: MatchIPOnly, IP: "203.0.113.13", Promoted: true, ExpiresAt: t0.Unix() - 1},  // expired already: never written
	}}
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/feed/list.json" {
			t.Errorf("the hub was asked %s %s: this test's install is registered and has its handle name", r.Method, r.URL.Path)
		}
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
	// A registered install, and the hub's other addresses on this server:
	// start() below is what a daemon runs, the register and the handle name
	// included.
	cur.CommunityBans.RegisterURL = srv.URL + "/api/feed/register"
	cur.CommunityBans.Token = "registered-once"
	cur.CommunityBans.HN = "swift-otter-a3f7"
	clock := t0
	newClient := func() *Client {
		return &Client{
			UserAgent:      "unmask-test",
			SettingsGetter: func() settings.Settings { return cur },
			SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
			MapDir:         dir,
			now:            func() time.Time { return clock },
		}
	}
	c := newClient()
	ctx := t.Context()
	keys := func(file string) string {
		t.Helper()
		set := map[string]struct{}{}
		if err := loadMapKeys(filepath.Join(dir, file), set); err != nil {
			t.Fatal(err)
		}
		var out []string
		for k := range set {
			out = append(out, k)
		}
		return strings.Join(sorted(out), " ")
	}
	hit := func(c *Client, ip, ja4 string) bool {
		_, ok := c.Matcher().Hit(ip, ja4)
		return ok
	}

	if _, err := c.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if got := keys(MapFileIP); got != "203.0.113.11 203.0.113.9" {
		t.Fatalf("after the pull the address map holds %q", got)
	}
	if got := keys(MapFileIPJA4); got != "203.0.113.10:"+botJA4b {
		t.Fatalf("after the pull the (address, fingerprint) map holds %q", got)
	}
	statePath := filepath.Join(dir, "community-bans-state.json")
	st, err := loadGuardState(statePath)
	if err != nil || len(st.Enforced) != 2 {
		t.Fatalf("the state on disk names %d expiring entries (err %v), want the two that are in the files and expire: %+v", len(st.Enforced), err, st.Enforced)
	}

	// The hub goes away.  Half an hour on nothing has expired: the install
	// goes on enforcing what the last pull gave it.
	down.Store(true)
	clock = t0.Add(30 * time.Minute)
	if _, err := c.Pull(ctx); err == nil {
		t.Fatal("the pull succeeded against a hub that answers 502")
	}
	if got := keys(MapFileIP); got != "203.0.113.11 203.0.113.9" || !hit(c, "203.0.113.9", "") {
		t.Errorf("half an hour without the hub: the address map holds %q", got)
	}

	// Two hours on, the first entry has passed its expiry and leaves; the
	// one with three hours and the one with none stay.
	clock = t0.Add(2 * time.Hour)
	if _, err := c.Pull(ctx); err == nil {
		t.Fatal("the pull succeeded against a hub that answers 502")
	}
	if got := keys(MapFileIP); got != "203.0.113.11" {
		t.Errorf("two hours without the hub: the address map holds %q, want 203.0.113.11 alone", got)
	}
	if got := keys(MapFileIPJA4); got != "203.0.113.10:"+botJA4b {
		t.Errorf("two hours without the hub: the (address, fingerprint) map holds %q", got)
	}
	if hit(c, "203.0.113.9", "") || !hit(c, "203.0.113.11", "") || !hit(c, "203.0.113.10", botJA4b) {
		t.Error("two hours without the hub: the daemon's own matcher does not follow the files")
	}
	if st, _ := loadGuardState(statePath); len(st.Enforced) != 1 || st.Applied["ip_only:203.0.113.9"] != 0 || st.Applied["ip_only:203.0.113.11"] == 0 {
		t.Errorf("two hours without the hub: the state on disk: %+v", st)
	}

	// The daemon restarts with the hub still away: the expiry is on disk,
	// not in the memory of the process that made the pull.
	clock = t0.Add(4 * time.Hour)
	c2 := newClient()
	c2.start(ctx)
	if got := keys(MapFileIPJA4); got != "" {
		t.Errorf("four hours without the hub, after a restart: the (address, fingerprint) map holds %q, want nothing", got)
	}
	if got := keys(MapFileIP); got != "203.0.113.11" {
		t.Errorf("four hours without the hub: the address map holds %q; the entry with no expiry stays", got)
	}
	if hit(c2, "203.0.113.10", botJA4b) || !hit(c2, "203.0.113.11", "") {
		t.Error("after the restart the matcher does not follow the files")
	}

	// Only ever out.  A state older than the files -- a mode switched in
	// between, a file from another daemon -- puts nothing back, and takes
	// out nothing it does not name.
	if err := os.WriteFile(filepath.Join(dir, MapFileIP), []byte("# by hand\n\"198.51.100.77\" 1;\n\"203.0.113.11\" 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ = loadGuardState(statePath)
	st.Enforced = []enforcedEntry{
		{Match: MatchIPOnly, IP: "203.0.113.50", ExpiresAt: t0.Unix() + 100*hour}, // not in the file, not expired
		{Match: MatchIPOnly, IP: "203.0.113.51", ExpiresAt: t0.Unix() + 1*hour},   // not in the file, expired
	}
	if err := saveGuardState(statePath, st); err != nil {
		t.Fatal(err)
	}
	c3 := newClient()
	if _, err := c3.Pull(ctx); err == nil {
		t.Fatal("the pull succeeded against a hub that answers 502")
	}
	if got := keys(MapFileIP); got != "198.51.100.77 203.0.113.11" {
		t.Errorf("a state that names what the file does not hold: the address map holds %q, want it as it was", got)
	}

	// The hub is back and lists the first entry again, with a new expiry:
	// it is applied again.
	down.Store(false)
	doc.Entries[0].ExpiresAt = clock.Unix() + 24*hour
	if _, err := c3.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if got := keys(MapFileIP); got != "203.0.113.11 203.0.113.9" {
		t.Errorf("the hub is back: the address map holds %q", got)
	}
}

// With the feed switched to listing only, or off, nothing is in the files
// and the state names nothing to expire.
func TestNothingToExpireWhenNothingIsApplied(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	doc := FeedDocument{GeneratedAt: now.Unix(), Version: 2, Entries: []FeedEntry{
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true, ExpiresAt: now.Unix() + 3600},
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
	statePath := filepath.Join(dir, "community-bans-state.json")
	enforced := func() int {
		t.Helper()
		st, err := loadGuardState(statePath)
		if err != nil {
			t.Fatal(err)
		}
		return len(st.Enforced)
	}
	if _, err := c.Pull(t.Context()); err != nil || enforced() != 1 {
		t.Fatalf("applying: err %v, %d expiring entries in the state, want 1", err, enforced())
	}
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetch
	if _, err := c.Pull(t.Context()); err != nil || enforced() != 0 {
		t.Errorf("listing only: err %v, %d expiring entries in the state, want none", err, enforced())
	}
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	if _, err := c.Pull(t.Context()); err != nil || enforced() != 1 {
		t.Fatalf("applying again: err %v, %d expiring entries", err, enforced())
	}
	cur.CommunityBans.SubscribeMode = settings.SubscribeOff
	if _, err := c.Pull(t.Context()); err != nil || enforced() != 0 {
		t.Errorf("off: err %v, %d expiring entries in the state, want none", err, enforced())
	}
}

func sorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
