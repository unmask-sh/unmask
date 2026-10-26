package communitybans

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	chromeJA4 = "t13d1516h2_8daaf6152771_b0da82dd1658" // a fingerprint Chromium sends
	botJA4    = "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb"
	botJA4b   = "t13d0000h1_cccccccccccc_dddddddddddd"
)

// keysOf lists the entries' keys, sorted: the order of what a pull applies
// is not a property (WriteMapFiles sorts the maps).
func keysOf(entries []FeedEntry) []string {
	out := []string{}
	for _, e := range entries {
		out = append(out, MuteKey(e))
	}
	sort.Strings(out)
	return out
}

// A ja4_only entry on a fingerprint a current browser sends is never
// applied, however long it has been promoted; the other kinds are.
func TestGuardNeverAppliesABrowserFingerprint(t *testing.T) {
	now := time.Now()
	st := newGuardState()
	entries := []FeedEntry{
		{Match: MatchJA4, JA4: chromeJA4, Promoted: true},
		{Match: MatchJA4, JA4: botJA4, Promoted: true},
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true},
		{Match: MatchIPJA4, IP: "203.0.113.10", JA4: chromeJA4, Promoted: true}, // bound to an address: fine
		{Match: MatchIPOnly, IP: "203.0.113.11"},                                // not promoted: untouched
	}
	st.SeenPromoted["ja4_only:"+chromeJA4] = now.Add(-10 * 24 * time.Hour).Unix()
	st.SeenPromoted["ja4_only:"+botJA4] = now.Add(-2 * 24 * time.Hour).Unix()
	observePromoted(entries, st, now)
	kept, held, p := guardEntries(entries, st, now)
	if got, want := strings.Join(keysOf(kept), " "), "ip_ja4:203.0.113.10|"+chromeJA4+" ip_only:203.0.113.11 ip_only:203.0.113.9 ja4_only:"+botJA4; got != want {
		t.Errorf("kept = %q, want %q", got, want)
	}
	if held["ja4_only:"+chromeJA4] != PendingMajors || len(held) != 1 {
		t.Errorf("held = %v", held)
	}
	if p.Majors != 1 || p.Grace != 0 || p.Capped != 0 || p.Total() != 1 {
		t.Errorf("pending = %+v", p)
	}
}

// A new ja4_only entry waits a day from the first sight of it promoted;
// an address entry does not wait.  The clock starts over when the entry
// leaves the promoted set and returns.
func TestGuardGraceForANewJA4OnlyEntry(t *testing.T) {
	t0 := time.Now()
	st := newGuardState()
	entries := []FeedEntry{
		{Match: MatchJA4, JA4: botJA4, Promoted: true},
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true},
	}
	observePromoted(entries, st, t0)
	kept, held, p := guardEntries(entries, st, t0)
	if got := strings.Join(keysOf(kept), " "); got != "ip_only:203.0.113.9" {
		t.Errorf("first sight: kept = %q, want the address alone", got)
	}
	if held["ja4_only:"+botJA4] != PendingGrace || p.Grace != 1 {
		t.Errorf("first sight: held = %v pending = %+v", held, p)
	}
	// An hour short of a day: still waiting.
	t1 := t0.Add(23 * time.Hour)
	observePromoted(entries, st, t1)
	if kept, _, p := guardEntries(entries, st, t1); len(kept) != 1 || p.Grace != 1 {
		t.Errorf("23h: kept = %v pending = %+v", keysOf(kept), p)
	}
	// A day on: applied.
	t2 := t0.Add(GraceJA4 + time.Minute)
	observePromoted(entries, st, t2)
	kept, held, p = guardEntries(entries, st, t2)
	if got := strings.Join(keysOf(kept), " "); got != "ip_only:203.0.113.9 ja4_only:"+botJA4 {
		t.Errorf("after the grace: kept = %q", got)
	}
	if len(held) != 0 || p.Total() != 0 {
		t.Errorf("after the grace: held = %v pending = %+v", held, p)
	}
	// Withdrawn, then promoted again: a new clock.
	entries[0].Promoted = false
	observePromoted(entries, st, t2.Add(time.Hour))
	if _, ok := st.SeenPromoted["ja4_only:"+botJA4]; ok {
		t.Error("an entry no longer promoted is still on the clock")
	}
	entries[0].Promoted = true
	t3 := t2.Add(2 * time.Hour)
	observePromoted(entries, st, t3)
	if _, _, p := guardEntries(entries, st, t3); p.Grace != 1 {
		t.Errorf("promoted again: pending = %+v, want the grace to start over", p)
	}
}

// One pull applies at most ApplyCap entries new to the install, the oldest
// on the hub first; the rest follow on the next pulls.  What was applied
// stays applied.
func TestGuardCapsWhatOnePullApplies(t *testing.T) {
	now := time.Now()
	st := newGuardState()
	var entries []FeedEntry
	for i := 0; i < ApplyCap*2+50; i++ {
		entries = append(entries, FeedEntry{Match: MatchIPOnly, IP: fmt.Sprintf("203.0.%d.%d", i/256, i%256), Promoted: true, FirstSeen: int64(1000 - i)})
	}
	observePromoted(entries, st, now)
	kept, held, p := guardEntries(entries, st, now)
	if len(kept) != ApplyCap || p.Capped != ApplyCap+50 || len(held) != ApplyCap+50 {
		t.Fatalf("first pull: kept %d held %d pending %+v", len(kept), len(held), p)
	}
	// The oldest first: the last entries of the slice have the smallest FirstSeen.
	keptKeys := map[string]bool{}
	for _, e := range kept {
		keptKeys[MuteKey(e)] = true
	}
	for _, e := range entries[len(entries)-ApplyCap:] {
		if !keptKeys[MuteKey(e)] {
			t.Errorf("%s (FirstSeen %d) was not among the oldest %d applied", e.IP, e.FirstSeen, ApplyCap)
			break
		}
	}
	for _, e := range held {
		if e != PendingCapped {
			t.Fatalf("held for %q, want %q", e, PendingCapped)
		}
	}
	later := now.Add(time.Hour)
	observePromoted(entries, st, later)
	kept, _, p = guardEntries(entries, st, later)
	if len(kept) != 2*ApplyCap || p.Capped != 50 {
		t.Fatalf("second pull: kept %d pending %+v", len(kept), p)
	}
	for _, e := range entries[len(entries)-ApplyCap:] {
		if _, ok := st.Applied[MuteKey(e)]; !ok {
			t.Errorf("%s applied by the first pull is not applied by the second", e.IP)
			break
		}
	}
	kept, _, p = guardEntries(entries, st, later.Add(time.Hour))
	if len(kept) != len(entries) || p.Total() != 0 {
		t.Errorf("third pull: kept %d pending %+v", len(kept), p)
	}
}

// The state survives a restart: written and read back whole; a missing
// file is an empty state, a broken one is an error and an empty state.
func TestGuardStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "community-bans-state.json")
	st, err := loadGuardState(path)
	if err != nil || len(st.SeenPromoted) != 0 || len(st.Applied) != 0 {
		t.Fatalf("missing file: %+v %v", st, err)
	}
	st.SeenPromoted["ja4_only:"+botJA4] = 1700000000
	st.Applied["ip_only:203.0.113.9"] = 1700000100
	if err := saveGuardState(path, st); err != nil {
		t.Fatal(err)
	}
	back, err := loadGuardState(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.SeenPromoted["ja4_only:"+botJA4] != 1700000000 || back.Applied["ip_only:203.0.113.9"] != 1700000100 || len(back.SeenPromoted) != 1 || len(back.Applied) != 1 {
		t.Errorf("read back: %+v", back)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = loadGuardState(path)
	if err == nil || st == nil || len(st.SeenPromoted) != 0 {
		t.Errorf("broken file: %+v %v", st, err)
	}
}

// Through Pull: the guards act on what reaches the map files and the
// matcher, the page sees what was held back and why, and the state is on
// disk for the next daemon.
func TestPullHoldsBackWhatTheGuardsSay(t *testing.T) {
	dir := t.TempDir()
	doc := FeedDocument{GeneratedAt: time.Now().Unix(), Version: 2, Entries: []FeedEntry{
		{Match: MatchJA4, JA4: chromeJA4, Promoted: true, Score: 5},
		{Match: MatchJA4, JA4: botJA4, Promoted: true, Score: 4},
		{Match: MatchIPOnly, IP: "203.0.113.9", Promoted: true, Score: 3},
		{Match: MatchIPJA4, IP: "203.0.113.10", JA4: botJA4b, Promoted: true, Score: 3},
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
	ctx := t.Context()
	if _, err := c.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if m := read(MapFileJA4); strings.Contains(m, chromeJA4) || strings.Contains(m, botJA4) {
		t.Errorf("the first pull wrote a held ja4_only entry:\n%s", m)
	}
	if m := read(MapFileIP); !strings.Contains(m, `"203.0.113.9" 1;`) {
		t.Errorf("the address entry is not in the map:\n%s", m)
	}
	if m := read(MapFileIPJA4); !strings.Contains(m, botJA4b) {
		t.Errorf("the (address, fingerprint) entry is not in the map:\n%s", m)
	}
	if p := c.Pending(); p.Majors != 1 || p.Grace != 1 || p.Capped != 0 {
		t.Errorf("pending after the first pull = %+v", p)
	}
	if k := c.PendingKinds(); k["ja4_only:"+chromeJA4] != PendingMajors || k["ja4_only:"+botJA4] != PendingGrace || len(k) != 2 {
		t.Errorf("pending kinds = %v", k)
	}
	if kind, hit := c.Matcher().Hit("198.51.100.1", botJA4); hit {
		t.Errorf("the matcher enforces the held entry (%s)", kind)
	}
	if _, hit := c.Matcher().Hit("203.0.113.9", ""); !hit {
		t.Error("the matcher does not enforce the address entry")
	}
	statePath := filepath.Join(dir, "community-bans-state.json")
	st, err := loadGuardState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.SeenPromoted["ja4_only:"+botJA4]; !ok {
		t.Errorf("the state on disk does not date the new ja4_only entry: %+v", st)
	}
	if _, ok := st.Applied["ip_only:203.0.113.9"]; !ok {
		t.Errorf("the state on disk does not list what was applied: %+v", st)
	}

	// A day later (the clock moved on disk, the daemon restarted): the bot's
	// fingerprint is applied; the browser's never.
	st.SeenPromoted["ja4_only:"+botJA4] = time.Now().Add(-GraceJA4 - time.Minute).Unix()
	if err := saveGuardState(statePath, st); err != nil {
		t.Fatal(err)
	}
	c2 := &Client{UserAgent: "unmask-test", SettingsGetter: c.SettingsGetter, SettingsUpdate: c.SettingsUpdate, MapDir: dir}
	if _, err := c2.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if m := read(MapFileJA4); !strings.Contains(m, botJA4) || strings.Contains(m, chromeJA4) {
		t.Errorf("after the grace:\n%s", m)
	}
	if p := c2.Pending(); p.Majors != 1 || p.Grace != 0 || p.Capped != 0 {
		t.Errorf("pending after the grace = %+v", p)
	}
	if _, hit := c2.Matcher().Hit("198.51.100.1", botJA4); !hit {
		t.Error("the matcher does not enforce the entry after its grace")
	}

	// Fetch only: nothing applied, nothing pending, and the next switch to
	// fetch_apply starts under the cap.
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetch
	if _, err := c2.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if m := read(MapFileIP); strings.Contains(m, "203.0.113.9") {
		t.Errorf("fetch only, the map still enforces:\n%s", m)
	}
	if p := c2.Pending(); p.Total() != 0 {
		t.Errorf("fetch only, pending = %+v", p)
	}
	st, _ = loadGuardState(statePath)
	if len(st.Applied) != 0 {
		t.Errorf("fetch only, the state still lists applied entries: %+v", st.Applied)
	}
	if _, ok := st.SeenPromoted["ja4_only:"+botJA4]; !ok {
		t.Error("fetch only, the clock of the ja4_only entry was dropped")
	}
}
