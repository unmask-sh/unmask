// Limits on what one pull of the feed may switch on.
//
// The feed is fetched over TLS and nothing else vouches for its content: a
// hub that was taken over, or a mistake made there, promotes entries that
// every subscriber enforces within the hour.  The bypass guard keeps the
// addresses that must never be touched out of the maps; these limits make
// any other change slow and small, which is time for someone to notice:
//
//   - a ja4_only entry whose JA4 is one a current browser sends
//     (nginxconf.MajorBrowserJA4) is never applied: it would challenge every
//     visitor on that browser, on every subscribed install at once;
//   - a ja4_only entry is applied a day after this install first saw it
//     promoted (GraceJA4), so a wrong one can be withdrawn before it reaches
//     visitors;
//   - one pull applies at most ApplyCap entries it did not apply before; the
//     rest follow on later pulls, the oldest first.
//
// An address entry has no grace: an address is one client, and the bypass
// guard covers the ranges that matter.  What the install has seen and
// applied is kept in a small state file, so the clocks survive a restart.
package communitybans

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

const (
	// GraceJA4 is how long a promoted ja4_only entry waits before it is
	// applied.
	GraceJA4 = 24 * time.Hour
	// ApplyCap is how many entries one pull may apply that it did not apply
	// before.
	ApplyCap = 200
	// DefaultStatePath is where the guard's state lives.
	DefaultStatePath = "/var/lib/unmask/community-bans-state.json"
)

// Why an entry is held back (Pending, PendingKinds).
const (
	PendingMajors = "majors" // a current browser's fingerprint: never applied
	PendingGrace  = "grace"  // inside its first day as a promoted entry
	PendingCapped = "capped" // over this pull's cap; a later pull applies it
)

// guardState is what the install remembers between pulls.
type guardState struct {
	// SeenPromoted: when a promoted ja4_only entry was first seen, by its
	// MuteKey.  An entry that leaves the promoted set and returns starts
	// over.
	SeenPromoted map[string]int64 `json:"seen_promoted,omitempty"`
	// Applied: the entries the last pull applied, by MuteKey, and when they
	// were first applied.  The cap counts what is not here.
	Applied map[string]int64 `json:"applied,omitempty"`
}

func newGuardState() *guardState {
	return &guardState{SeenPromoted: map[string]int64{}, Applied: map[string]int64{}}
}

// loadGuardState reads the state file; a missing one is an empty state.
func loadGuardState(path string) (*guardState, error) {
	st := newGuardState()
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return newGuardState(), err
	}
	if st.SeenPromoted == nil {
		st.SeenPromoted = map[string]int64{}
	}
	if st.Applied == nil {
		st.Applied = map[string]int64{}
	}
	return st, nil
}

// saveGuardState writes the state file atomically.
func saveGuardState(path string, st *guardState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Pending counts the promoted entries the last pull held back, and why.
type Pending struct {
	Majors int // ja4_only entries that are a current browser's fingerprint
	Grace  int // ja4_only entries inside their first day
	Capped int // entries over the pull's cap, waiting for a later pull
	At     time.Time
}

// Total is how many entries are held back in all.
func (p Pending) Total() int { return p.Majors + p.Grace + p.Capped }

// applies reports whether WriteMapFiles would write the entry: promoted and
// not expired.  The guards look at nothing else.
func applies(e FeedEntry, now int64) bool {
	return e.Promoted && !(e.ExpiresAt > 0 && e.ExpiresAt < now)
}

// isJA4Only: the entry is matched by fingerprint alone.
func isJA4Only(e FeedEntry) bool {
	return strings.HasPrefix(MuteKey(e), "ja4_only:")
}

// observePromoted records when each promoted ja4_only entry was first seen,
// and forgets the ones no longer promoted.  Run on every pull that reaches
// the hub, so the clock runs while the install only reads the feed too.
func observePromoted(entries []FeedEntry, st *guardState, now time.Time) {
	seen := map[string]bool{}
	for _, e := range entries {
		if !applies(e, now.Unix()) || !isJA4Only(e) {
			continue
		}
		key := MuteKey(e)
		seen[key] = true
		if _, ok := st.SeenPromoted[key]; !ok {
			st.SeenPromoted[key] = now.Unix()
		}
	}
	for key := range st.SeenPromoted {
		if !seen[key] {
			delete(st.SeenPromoted, key)
		}
	}
}

// guardEntries returns the entries this pull applies, the ones it holds
// back by MuteKey with the reason, and the counts; it updates st (what was
// seen, what is applied now).  Entries that WriteMapFiles would not write
// pass through untouched.
// observePromoted has run on the feed before this.
func guardEntries(entries []FeedEntry, st *guardState, now time.Time) (kept []FeedEntry, held map[string]string, p Pending) {
	held = map[string]string{}
	p.At = now
	nowSec := now.Unix()
	kept = make([]FeedEntry, 0, len(entries))
	// Candidates the cap decides on: entries not applied by the last pull,
	// the oldest on the hub first, so what follows is predictable.
	var fresh []FeedEntry
	applied := map[string]int64{}
	for _, e := range entries {
		key := MuteKey(e)
		if !applies(e, nowSec) || key == "" {
			kept = append(kept, e) // not written anyway (WriteMapFiles)
			continue
		}
		if isJA4Only(e) {
			if nginxconf.MajorBrowserJA4(e.JA4) {
				held[key] = PendingMajors
				p.Majors++
				continue
			}
			if first, ok := st.SeenPromoted[key]; ok && nowSec-first < int64(GraceJA4/time.Second) {
				held[key] = PendingGrace
				p.Grace++
				continue
			}
		}
		if at, ok := st.Applied[key]; ok {
			applied[key] = at
			kept = append(kept, e)
			continue
		}
		fresh = append(fresh, e)
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		a, b := fresh[i], fresh[j]
		if a.FirstSeen != b.FirstSeen {
			return a.FirstSeen < b.FirstSeen
		}
		return MuteKey(a) < MuteKey(b)
	})
	for n, e := range fresh {
		key := MuteKey(e)
		if n >= ApplyCap {
			held[key] = PendingCapped
			p.Capped++
			continue
		}
		applied[key] = nowSec
		kept = append(kept, e)
	}
	st.Applied = applied
	return kept, held, p
}
