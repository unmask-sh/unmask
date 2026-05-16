// preset lookup helpers.  Core of the rename-safe ID binding.
//
// Design:
//   - JA4VerdictRule.ID (= 1-99 built-in / 100+ extra) is the immutable key
//     stored in DB column unmask_event.ja4_verdict_id.
//   - When rendering dashboard / settings, look up ID -> current Verdict
//     (= the preset's Verdict field) for display.  Renaming a preset only
//     requires changing the Verdict field.
//
// merge:
//   Aggregate built-in (= JA4VerdictGroups) and extra
//   (= settings.Nginx.JA4Verdicts.Extra) by ID.  If extra ever overlaps a
//   built-in ID, extra wins (= defensive — should not happen in practice).
//   Normally extra IDs are 100+ so collisions don't occur.
package nginxconf

import (
	"fmt"
)

// VerdictPreset: lookup-friendly view of one verdict rule.
// JA4VerdictRule + origin (built-in/extra) + group info.
type VerdictPreset struct {
	ID         int
	Verdict    string // current display name
	Action     string // bot / suspect / ok
	Pattern    string
	IsExtra    bool   // false=built-in, true=extra
	GroupID    string // built-in only.  empty for extra
	GroupLabel string
}

// VerdictRegistry: aggregation that supports lookup by ID and by name.
// Pass in extra rules to resolve "built-in + extra" in one call.
//
// Expected to be rebuilt by calling BuildVerdictRegistry every time at
// startup / on settings change (= no cache, build on demand).  At a scale
// of dozens of entries the overhead is negligible.
type VerdictRegistry struct {
	byID   map[int]VerdictPreset
	byName map[string]VerdictPreset
}

// ExtraVerdict: a user-added verdict preset coming from settings.
// To avoid depending on the settings package's struct, this is a minimal
// interface only.
type ExtraVerdict struct {
	ID      int
	Verdict string
	Action  string
	Pattern string
}

// BuildVerdictRegistry: build the registry from built-in
// (JA4VerdictGroups) + extra.
//
// If extra is empty, built-in only.  If an extra ID collides with a
// built-in ID, the extra wins (= last-write-wins; collisions are not
// expected in normal operation).
func BuildVerdictRegistry(extra []ExtraVerdict) *VerdictRegistry {
	r := &VerdictRegistry{
		byID:   make(map[int]VerdictPreset, 32),
		byName: make(map[string]VerdictPreset, 32),
	}
	for _, g := range JA4VerdictGroups {
		for _, rule := range g.Rules {
			p := VerdictPreset{
				ID:         rule.ID,
				Verdict:    rule.Verdict,
				Action:     rule.Action,
				Pattern:    rule.Pattern,
				IsExtra:    false,
				GroupID:    g.ID,
				GroupLabel: g.Label,
			}
			if rule.ID > 0 {
				r.byID[rule.ID] = p
			}
			if rule.Verdict != "" {
				r.byName[rule.Verdict] = p
			}
		}
	}
	for _, e := range extra {
		p := VerdictPreset{
			ID:      e.ID,
			Verdict: e.Verdict,
			Action:  e.Action,
			Pattern: e.Pattern,
			IsExtra: true,
		}
		if e.ID > 0 {
			r.byID[e.ID] = p
		}
		if e.Verdict != "" {
			r.byName[e.Verdict] = p
		}
	}
	return r
}

// IDToVerdict: ID -> current Verdict name (= for display).  Returns "" for unknown IDs.
func (r *VerdictRegistry) IDToVerdict(id int) string {
	if r == nil || id <= 0 {
		return ""
	}
	if p, ok := r.byID[id]; ok {
		return p.Verdict
	}
	return ""
}

// NameToID: Verdict name -> ID.  Returns 0 for unknown names.
func (r *VerdictRegistry) NameToID(name string) int {
	if r == nil || name == "" {
		return 0
	}
	if p, ok := r.byName[name]; ok {
		return p.ID
	}
	return 0
}

// IDToAction: ID -> action enum.  Returns "" for unknown IDs
// (= callers should treat that as "ok" equivalent for display).
func (r *VerdictRegistry) IDToAction(id int) string {
	if r == nil || id <= 0 {
		return ""
	}
	if p, ok := r.byID[id]; ok {
		return p.Action
	}
	return ""
}

// ResolveDisplay: given a DB row (id, raw_name) pair, return the display name.
//   - id present in registry  -> the preset's current Verdict (= rename-aware).
//   - id unknown (= 0 / old row / not in registry) -> fall back to raw_name.
//   - both empty -> "".
//
// Used by the display layer (dashboard / hunt / etc.).
func (r *VerdictRegistry) ResolveDisplay(id int, rawName string) string {
	if r != nil && id > 0 {
		if p, ok := r.byID[id]; ok {
			return p.Verdict
		}
	}
	return rawName
}

// BotIDs: return the slice of rule IDs whose action is bot/suspect
// (= IsBotAction true).  Used to build SQL `ja4_verdict_id IN (?, ?, ...)`.
// Order is unspecified.
func (r *VerdictRegistry) BotIDs() []int {
	if r == nil {
		return nil
	}
	out := make([]int, 0, len(r.byID))
	for id, p := range r.byID {
		if id > 0 && IsBotAction(p.Action) {
			out = append(out, id)
		}
	}
	return out
}

// AllNameToID: return a copy of the name -> ID map from the registry.
// For passing to db.BackfillVerdictIDs.  This is a read-only snapshot, so
// the caller can use it freely.
func (r *VerdictRegistry) AllNameToID() map[string]int {
	if r == nil {
		return nil
	}
	out := make(map[string]int, len(r.byName))
	for n, p := range r.byName {
		if p.ID > 0 && n != "" {
			out[n] = p.ID
		}
	}
	return out
}

// AssignExtraID: assign a new ID to an extra entry while avoiding collisions
// with existing extras.
//
// Rules:
//   - Don't use built-in IDs (= 1-99) (= a collision would break things when
//     a built-in is renamed).
//   - Return max(existing extra ID) + 1 starting from 100.
//   - Return 100 if extras is empty.
//
// Returns 0 if assignment is impossible (= should not happen).
func AssignExtraID(extras []ExtraVerdict) int {
	maxID := 99 // base 99 so the next candidate is 100
	for _, e := range extras {
		if e.ID > maxID {
			maxID = e.ID
		}
	}
	return maxID + 1
}

// FormatVerdictForLog: human-friendly notation for log / debug
// (= "<id>:<name>" etc.).  Used mostly for diagnostic output.
func FormatVerdictForLog(id int, name string) string {
	if id > 0 && name != "" {
		return fmt.Sprintf("%d:%s", id, name)
	}
	if id > 0 {
		return fmt.Sprintf("%d", id)
	}
	return name
}
