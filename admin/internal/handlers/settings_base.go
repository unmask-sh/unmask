package handlers

import (
	"errors"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A settings page carries, in each of its forms, the version of the
// settings it showed (_base: settings.Version of SavedYAML).  A save from a
// page opened before another one landed -- a second tab, a second operator,
// the CLI -- used to apply the whole form over the settings as they were by
// then, so every field the form carries went back to what that page showed
// and the other change was lost without a word (review finding H11).  The
// save now merges three ways (mergeStaleSave): what the page showed, the
// save, and the settings as they are.

// settingsBases keeps the settings as recent pages showed them -- SavedYAML's
// text by version -- for such a merge.  In memory only: after a restart a
// save from a page opened before it is refused, and the page reloaded.
type settingsBases struct {
	mu    sync.Mutex
	order []string
	byVer map[string]string
}

// settingsBasesMax: the versions kept.  One per save, and the pages shown in
// between share theirs: dozens cover a long editing session.
const settingsBasesMax = 32

// rememberSettingsBase records s as a page shows it and returns its version,
// for the page's forms to carry.  "" when s does not encode (the save then
// works as it did, with no merge).
func (h *Handler) rememberSettingsBase(s settings.Settings) string {
	text, err := settings.SavedYAML(s)
	if err != nil {
		return ""
	}
	v := settings.Version(text)
	b := &h.settingsBases
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byVer == nil {
		b.byVer = map[string]string{}
	}
	if _, ok := b.byVer[v]; ok {
		for i, o := range b.order {
			if o == v {
				b.order = append(b.order[:i], b.order[i+1:]...)
				break
			}
		}
	} else {
		b.byVer[v] = text
	}
	b.order = append(b.order, v)
	for len(b.order) > settingsBasesMax {
		delete(b.byVer, b.order[0])
		b.order = b.order[1:]
	}
	return v
}

func (h *Handler) settingsBase(v string) (string, bool) {
	b := &h.settingsBases
	b.mu.Lock()
	defer b.mu.Unlock()
	text, ok := b.byVer[v]
	return text, ok
}

// errStaleBaseUnknown: the page's version is not among those kept (a
// restart since, or a page left open past dozens of saves).
var errStaleBaseUnknown = errors.New("stale base unknown")

// staleConflictError: the page's save and a later one changed the same
// settings, differently.
type staleConflictError struct{ paths []string }

func (e *staleConflictError) Error() string {
	return "conflicting changes: " + strings.Join(e.paths, ", ")
}

// mergeStaleSave turns cur -- the settings as they are now (theirs, its
// SavedYAML text), with the page's form applied -- into the three-way merge
// of the page's version (base), that save and theirs: a setting only the
// page changed keeps the page's value, one only the later change touched
// keeps that, and one both changed differently is a staleConflictError.
func (h *Handler) mergeStaleSave(cur *settings.Settings, base, theirs string) error {
	baseText, ok := h.settingsBase(base)
	if !ok {
		return errStaleBaseUnknown
	}
	ours, err := settings.SavedYAML(*cur)
	if err != nil {
		return err
	}
	merged, conflicts, err := settings.Merge3(baseText, ours, theirs)
	if err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &staleConflictError{paths: conflicts}
	}
	s, err := settings.LoadFromYAML(merged)
	if err != nil {
		return err
	}
	*cur = s
	return nil
}
