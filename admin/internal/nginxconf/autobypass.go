// autobypass.go: derive bypass-IP presets from the UA filter's standing
// intent.
//
// An operator who passes a vendor's crawler by UA string has already decided
// to let that vendor in; what the UA string cannot do is prove the visitor IS
// that vendor.  For vendors that publish egress ranges the stricter form of
// the same decision is available, and uarange.go's resolution already prefers
// it: the moment a vendor's preset is enabled, its UA-string rescue drops and
// only the published addresses pass.  What was missing is the first step --
// existing installs carry the preset list they saved, so a preset added in a
// later release sits unchecked forever and the vendor stays on name-only
// rescue (observed twice in production: an install challenged genuine
// Amazonbot for a month; another passed every ClaudeBot impostor).
//
// The rule here closes that half: a preset is enabled automatically when the
// operator's OWN config says the vendor's UA currently passes.  The visitors
// whose fate changes are exactly the impostors wearing the name.
//
// Guardrails, in order of importance:
//
//   - Freshness: the derivation refuses to act on stale address data
//     (AutoBypassMaxSnapshotAge).  Flipping a vendor from name-pass to
//     address-verification with an outdated range list would challenge the
//     genuine crawler -- the one accident this whole subsystem exists to
//     prevent.  A host that cannot sync keeps its build-time snapshot, whose
//     vintage snapshot-meta.json records; when that ages out the derivation
//     stops and doctor says why.
//   - Blocked vendors stay blocked: intent is read from the UA resolution
//     inputs (group mode + per-pattern disable), so a vendor the operator
//     challenges (group black / pattern disabled) is never granted an address
//     bypass -- bypass outranks the challenge axes, so getting this wrong
//     would override an explicit block.
//   - Derived, never persisted: the config file keeps exactly what the
//     operator wrote.  Opting a preset out is its own recorded decision
//     (BypassIPAutoExcluded), made in the UI by unchecking the auto row.
package nginxconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AutoBypassMaxSnapshotAge: the staleness ceiling past which the derivation
// stops enabling presets.  30 days holds the observed vendor cadence with
// room (OpenAI shipped 76 new ChatGPT-User prefixes in one August update;
// an install whose data is a month old must not be the one deciding that a
// crawler outside its list is an impostor).
const AutoBypassMaxSnapshotAge = 30 * 24 * time.Hour

// patternCategory: upstream crawler pattern -> primary rescue category, built
// once from the same source the rescue itself reads.  Used to resolve each
// pattern's group mode (white/black/none) without re-parsing the JSON per
// request.
var (
	patternCatOnce sync.Once
	patternCat     map[string]string
)

func patternCategories() map[string]string {
	patternCatOnce.Do(func() {
		patternCat = map[string]string{}
		for cat, entries := range classify.UpstreamRescueList() {
			for _, e := range entries {
				patternCat[e.Pattern] = cat
			}
		}
	})
	return patternCat
}

// SnapshotDataAt reports the freshest evidence of when this install's
// address data was assembled: the sync-written meta (or, for installs that
// synced before the meta existed, the newest override file's mtime), else
// the embed snapshot's meta.  Zero when nothing is dated (very old embeds);
// the derivation then treats the data as stale.
func SnapshotDataAt() time.Time {
	iprangeMu.RLock()
	dir := iprangeOverrideDir
	iprangeMu.RUnlock()

	var best time.Time
	consider := func(t time.Time) {
		if t.After(best) {
			best = t
		}
	}
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, snapshotMetaBase)); err == nil {
			var m snapshotMeta
			if json.Unmarshal(b, &m) == nil {
				if t, err := time.Parse(time.RFC3339, m.GeneratedAt); err == nil {
					consider(t)
				}
			}
		}
		// Pre-meta installs: the files themselves date the last sync.
		if entries, err := filepath.Glob(filepath.Join(dir, "*.json")); err == nil {
			for _, e := range entries {
				if fi, err := os.Stat(e); err == nil {
					consider(fi.ModTime())
				}
			}
		}
	}
	if b, err := assets.IPRange.ReadFile("iprange/" + snapshotMetaBase); err == nil {
		var m snapshotMeta
		if json.Unmarshal(b, &m) == nil {
			if t, err := time.Parse(time.RFC3339, m.GeneratedAt); err == nil {
				consider(t)
			}
		}
	}
	return best
}

// snapshotFreshEnough is the derivation's freshness gate, split out so tests
// can pin the boundary.
func snapshotFreshEnough(dataAt, now time.Time) bool {
	if dataAt.IsZero() {
		return false
	}
	return now.Sub(dataAt) <= AutoBypassMaxSnapshotAge
}

// AutoBypassPresetIDs returns the presets the auto-from-UA rule enables for
// this config, mapped to the UA patterns that justify each one (the UI and
// doctor name them).  Empty when the feature is off, the snapshot is stale,
// or no vendor qualifies.
// snapshotDataAtFn is a test seam: derivation tests pin the data vintage
// instead of inheriting the embed's real age (which would make the suite
// start failing by itself 30 days after every embed refresh).
var snapshotDataAtFn = SnapshotDataAt

func AutoBypassPresetIDs(n settings.Nginx) map[string][]string {
	if !n.BypassIPAutoFromUAEnabled() {
		return nil
	}
	if !snapshotFreshEnough(snapshotDataAtFn(), time.Now()) {
		return nil
	}
	return autoBypassPresetIDsUngated(n)
}

// AutoBypassSuspended reports whether the derivation is switched on and has
// vendors it WOULD enable, but is standing down because the address data is
// past the staleness ceiling.  Doctor surfaces this: the operator believes
// name-to-address verification is on, and silence would hide that it is not.
func AutoBypassSuspended(n settings.Nginx) (ids []string, dataAt time.Time, suspended bool) {
	if !n.BypassIPAutoFromUAEnabled() {
		return nil, time.Time{}, false
	}
	dataAt = snapshotDataAtFn()
	if snapshotFreshEnough(dataAt, time.Now()) {
		return nil, dataAt, false
	}
	would := autoBypassPresetIDsUngated(n)
	if len(would) == 0 {
		return nil, dataAt, false
	}
	for id := range would {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, dataAt, true
}

// autoBypassPresetIDsUngated is the intent resolution alone (no freshness
// gate); AutoBypassPresetIDs and AutoBypassSuspended share it.
func autoBypassPresetIDsUngated(n settings.Nginx) map[string][]string {
	explicit := map[string]bool{}
	for _, id := range n.BypassIPEnabledPresets {
		explicit[id] = true
	}
	excluded := map[string]bool{}
	for _, id := range n.BypassIPAutoExcluded {
		excluded[id] = true
	}
	disabled := map[string]bool{}
	for _, p := range n.SearchBots.UpstreamDisabled {
		disabled[p] = true
	}
	cats := patternCategories()

	// Intent is judged per PRESET, and a preset is vendor-wide while the UA
	// config is per-pattern: Google's ad crawlers and its search crawler ride
	// the same ranges.  Enabling the preset because one white pattern shows
	// intent would also address-pass every OTHER pattern the ranges back --
	// including one whose group the operator set to black, and bypass
	// outranks the challenge that black asked for.  So the bar is total: a
	// preset derives only when EVERY pattern it backs currently passes by UA
	// (group white, not disabled).  Anything short of that is a mixed signal,
	// and mixed signals are the operator's call, not this rule's.
	type tally struct {
		white  []string
		vetoed bool
	}
	tallies := map[string]*tally{}
	for pat, ids := range UARangePresets {
		cat, known := cats[pat]
		passes := known && !disabled[pat] &&
			classify.ResolveGroupMode(cat, n.SearchBots.UpstreamGroupMode) == classify.GroupModeWhite
		for _, id := range ids {
			if explicit[id] || excluded[id] {
				continue
			}
			tl := tallies[id]
			if tl == nil {
				tl = &tally{}
				tallies[id] = tl
			}
			if passes {
				tl.white = append(tl.white, pat)
			} else {
				tl.vetoed = true
			}
		}
	}
	out := map[string][]string{}
	for id, tl := range tallies {
		if tl.vetoed || len(tl.white) == 0 {
			continue
		}
		g := bypassIPGroupByID(id)
		if g == nil || g.PrefixCount() == 0 {
			continue
		}
		sort.Strings(tl.white)
		out[id] = tl.white
	}
	return out
}

// SetSnapshotDataAtForTests overrides the snapshot vintage the derivation
// reads and returns a restore func.  Test packages pin this so no test's
// outcome rides on the real embed's age -- which otherwise grows until the
// next release and flips the derivation (and every render it feeds) in CI
// months after the code last changed.
func SetSnapshotDataAtForTests(fn func() time.Time) (restore func()) {
	prev := snapshotDataAtFn
	snapshotDataAtFn = fn
	return func() { snapshotDataAtFn = prev }
}

// AutoBypassCandidateIDs: the presets the derivation could ever touch (= the
// ones some UA pattern is backed by).  The settings save uses it to scope
// opt-out bookkeeping to rows where an opt-out means something.
func AutoBypassCandidateIDs() map[string]bool {
	out := map[string]bool{}
	for _, ids := range UARangePresets {
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

// EffectiveBypassIPPresets is the preset list every consumer enforces: the
// operator's explicit list plus the auto-derived ones.  Explicit order is
// preserved (it is the saved order); derived IDs follow, sorted, so renders
// stay byte-stable across runs.
func EffectiveBypassIPPresets(n settings.Nginx) []string {
	auto := AutoBypassPresetIDs(n)
	if len(auto) == 0 {
		return n.BypassIPEnabledPresets
	}
	out := make([]string, 0, len(n.BypassIPEnabledPresets)+len(auto))
	out = append(out, n.BypassIPEnabledPresets...)
	ids := make([]string, 0, len(auto))
	for id := range auto {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return append(out, ids...)
}
