// Package renderwatch: whether the running nginx has loaded the
// configuration unmask last wrote, read from the access log nginx sends.
//
// The admin renders nginx's configuration on every settings save (and after
// the IP-range pull and a GeoIP update) and deliberately does not reload
// nginx: the operator owns that step.  Until the reload, what was saved is
// not live.  The process table would say when nginx last read its
// configuration, but the daemon's unit hides other users' processes
// (ProtectProc=invisible), so the daemon cannot look there.  The access log
// can say it instead: every rendered log line carries the render id of the
// configuration nginx loaded (rv=, see nginxconf.RenderIDOnDisk), and the
// http.inc on disk carries the id of the configuration written last.  A line
// naming another id after that file was written is nginx still running the
// older configuration.
//
// Only a native install (or the container gateway) sends the daemon its
// access log; a forward-auth install sends none, so nothing is ever seen and
// nothing is ever reported.
package renderwatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

const (
	// Grace: how long after a configuration is written a line from the
	// previous one does not count yet.  The container gateway reloads by
	// itself within seconds, and an operator who just saved is reading the
	// settings page's own reload prompt.
	Grace = time.Minute
	// StateFile: what the daemon saw, kept beside the rendered files so
	// `unmask doctor` -- which the admin runs as a child process, inside
	// the same unit -- can read it.
	StateFile = ".render-seen"
	// maxIDs: ids remembered at once.  A configuration changes a few times
	// a day at most; the bound only matters for something feeding the
	// socket made-up ids.
	maxIDs = 16
	// statEvery: how often State looks at http.inc again.
	statEvery = 5 * time.Second
)

// Watch keeps, per render id, when an access-log line last carried it.
type Watch struct {
	dir func() string // the render output dir; read on every State

	mu    sync.Mutex
	seen  map[string]time.Time // id on a line ("" = no rv= field) -> last line
	dirty bool

	// The configuration on disk, read again when http.inc changes.
	diskDir     string
	diskMod     time.Time
	diskSize    int64
	diskID      string
	diskWritten time.Time
	statAt      time.Time
}

// New: a watch over the configuration rendered into dir().
func New(dir func() string) *Watch {
	return &Watch{dir: dir, seen: map[string]time.Time{}}
}

// Saw records the render id one access-log line carried.  "" is a line with
// no rv= field: a configuration written before render ids, which is older
// than any configuration that has one.
func (w *Watch) Saw(id string, at time.Time) {
	if w == nil {
		return
	}
	w.mu.Lock()
	prev, ok := w.seen[id]
	// Nearly every line repeats the last one's id; a second's resolution is
	// all the comparison needs.
	if !ok || at.Sub(prev) >= time.Second {
		w.seen[id] = at
		w.dirty = true
		if !ok && len(w.seen) > maxIDs {
			w.pruneLocked()
		}
	}
	w.mu.Unlock()
}

// pruneLocked drops the ids seen longest ago down to maxIDs.
func (w *Watch) pruneLocked() {
	for len(w.seen) > maxIDs {
		var oldID string
		var oldAt time.Time
		first := true
		for id, at := range w.seen {
			if first || at.Before(oldAt) {
				oldID, oldAt, first = id, at, false
			}
		}
		delete(w.seen, oldID)
	}
}

// State: the comparison now.
func (w *Watch) State() State {
	if w == nil {
		return State{}
	}
	dir := ""
	if w.dir != nil {
		dir = w.dir()
	}
	now := time.Now()
	w.mu.Lock()
	recheck := dir != w.diskDir || now.Sub(w.statAt) >= statEvery
	w.mu.Unlock()
	if recheck {
		w.refreshDisk(dir, now)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return Evaluate(w.diskID, w.diskWritten, w.seen)
}

// Settle is State, and the consequence: once nginx has logged the
// configuration on disk, the reload marker the render left for it
// (nginxconf.ReloadNeededMarker) is removed -- for the id the marker names
// only, so a newer render's marker, written since the files were last looked
// at, stays.  The admin pages call it on every render of the reload notice,
// and the daemon every half minute, so the marker goes without a page view.
func (w *Watch) Settle() State {
	st := w.State()
	if st.Fresh() && w != nil && w.dir != nil {
		nginxconf.ClearReloadNeeded(w.dir(), st.Current)
	}
	return st
}

// refreshDisk reads the id of the configuration on disk when http.inc
// changed since the last look.  Outside the lock: it reads a file, and the
// access-log reader must not wait on that.
func (w *Watch) refreshDisk(dir string, now time.Time) {
	var mod time.Time
	var size int64
	if fi, err := os.Stat(filepath.Join(dir, "http.inc")); err == nil {
		mod, size = fi.ModTime(), fi.Size()
	}
	w.mu.Lock()
	same := dir == w.diskDir && mod.Equal(w.diskMod) && size == w.diskSize
	w.mu.Unlock()
	id, written := "", time.Time{}
	if same {
		w.mu.Lock()
		w.statAt = now
		w.mu.Unlock()
		return
	}
	if !mod.IsZero() {
		id, written = nginxconf.RenderIDOnDisk(dir)
	}
	w.mu.Lock()
	w.diskDir, w.diskMod, w.diskSize = dir, mod, size
	w.diskID, w.diskWritten = id, written
	w.statAt = now
	w.mu.Unlock()
}

// State is the comparison at one moment.
type State struct {
	// Current: the id of the configuration on disk.  "" when there is none
	// to compare: no http.inc, or one written before render ids.
	Current string
	// Written: when that configuration was written (http.inc's mtime).
	Written time.Time
	// Pending: nginx logged another configuration's id after Written plus
	// Grace and has not logged Current since Written.
	Pending bool
	// Running: the id the latest of those lines carried ("" = a
	// configuration from before render ids).  Pending only.
	Running string
	// LastStale: when nginx last logged a line from the older
	// configuration.  Pending only.
	LastStale time.Time
	// LastCurrent: when nginx last logged Current; zero when never.
	LastCurrent time.Time
}

// Fresh: nginx has logged the configuration on disk since it was written.
func (s State) Fresh() bool {
	return s.Current != "" && !s.LastCurrent.IsZero() && !s.LastCurrent.Before(s.Written)
}

// Evaluate is the comparison rule on its own, so `unmask doctor` applies the
// same one to the state file the daemon keeps.
//
// After a reload, nginx's old workers finish the connections they hold and
// keep logging the older id for a while; any line with the current id since
// the file was written settles it.  Before the reload there is no such line,
// and a line from the older configuration -- after the grace -- says nginx is
// behind.  No lines at all says nothing: no traffic is not a stale nginx.
func Evaluate(current string, written time.Time, seen map[string]time.Time) State {
	st := State{Current: current, Written: written}
	if current == "" {
		return st
	}
	st.LastCurrent = seen[current]
	var lastStale time.Time
	running := ""
	for id, at := range seen {
		if id != current && at.After(lastStale) {
			lastStale, running = at, id
		}
	}
	if lastStale.After(written.Add(Grace)) && st.LastCurrent.Before(written) {
		st.Pending, st.Running, st.LastStale = true, running, lastStale
	}
	return st
}

// stateDoc: the state file's shape.
type stateDoc struct {
	Seen map[string]time.Time `json:"seen"`
}

// Save writes what the watch saw to StateFile in the output dir, when it saw
// anything new since the last save.
func (w *Watch) Save() error {
	if w == nil {
		return nil
	}
	dir := ""
	if w.dir != nil {
		dir = w.dir()
	}
	w.mu.Lock()
	if !w.dirty || dir == "" {
		w.mu.Unlock()
		return nil
	}
	doc := stateDoc{Seen: make(map[string]time.Time, len(w.seen))}
	for id, at := range w.seen {
		doc.Seen[id] = at.UTC()
	}
	w.dirty = false
	w.mu.Unlock()
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, StateFile+".tmp-*")
	if err != nil {
		w.markDirty()
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		w.markDirty()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		w.markDirty()
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		w.markDirty()
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, StateFile)); err != nil {
		_ = os.Remove(tmp)
		w.markDirty()
		return err
	}
	return nil
}

func (w *Watch) markDirty() {
	w.mu.Lock()
	w.dirty = true
	w.mu.Unlock()
}

// Load takes back what an earlier run saved, so a restart does not forget
// that nginx was behind.  Lines seen since win over the file.  The render
// record beside it is brought up to the current rules on the way
// (nginxconf.ScrubRenderRecord): once per start, before any page reads it.
func (w *Watch) Load() {
	if w == nil || w.dir == nil {
		return
	}
	nginxconf.ScrubRenderRecord(w.dir())
	seen, err := LoadSeen(w.dir())
	if err != nil {
		return
	}
	w.mu.Lock()
	for id, at := range seen {
		if cur, ok := w.seen[id]; !ok || at.After(cur) {
			w.seen[id] = at
		}
	}
	if len(w.seen) > maxIDs {
		w.pruneLocked()
	}
	w.mu.Unlock()
}

// LoadSeen reads the state file in dir.
func LoadSeen(dir string) (map[string]time.Time, error) {
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		return nil, err
	}
	var doc stateDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Seen == nil {
		doc.Seen = map[string]time.Time{}
	}
	return doc.Seen, nil
}
