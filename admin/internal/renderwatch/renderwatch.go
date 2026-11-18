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
// The module nginx loaded is read the same way.  A package that places a
// new ngx_http_unmask_module.so leaves the running nginx on the old one --
// a reload does not load a module again, only a restart does -- and the
// line carries the hash of the module file nginx loaded (mo=, the module's
// $unmask_module_id) beside the render id.  The file at load_module's path
// (nginxconf.ModuleFilePath) hashes to what nginx should be running; a line
// naming another hash after that file was placed is an nginx that needs a
// restart, not a reload.
//
// What that module can verify is read there too.  The daemon is replaced by
// the package at once and nginx runs the module it loaded until it is
// restarted, so the daemon may know a form of pass the module in front of it
// does not: the line carries what the module says it verifies beyond the
// builds before it (mc=, the module's $unmask_module_caps -- words, "sig128"
// so far), and the daemon holds back a form until the lines answer for it
// (ModuleLacks).
//
// Only a native install (or the container gateway) sends the daemon its
// access log; a forward-auth install sends none, so nothing is ever seen and
// nothing is ever reported.
package renderwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

	// CapSig128: the word a module says when it verifies a pass whose
	// signature is 32 hex digits (0.1.58 and later).
	CapSig128 = "sig128"
)

// trackedCaps: the words the daemon asks about.  A line that does not carry
// one of these is remembered as such; a word no caller asks about is not
// kept at all.
var trackedCaps = []string{CapSig128}

// hasCap: whether caps -- words joined by commas, as the module writes them
// -- holds word.
func hasCap(caps, word string) bool {
	for caps != "" {
		w := caps
		if i := strings.IndexByte(caps, ','); i >= 0 {
			w, caps = caps[:i], caps[i+1:]
		} else {
			caps = ""
		}
		if w == word {
			return true
		}
	}
	return false
}

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

	// The module: modPath names the file nginx loads (nil = unknown, no
	// comparison), modSeen is what the lines carried (mo=; "" = a line
	// without the field, a module from before module ids), and the rest is
	// the file on disk, hashed again when it changes.
	modPath   func() string
	modSeen   map[string]time.Time
	modFile   string
	modMod    time.Time
	modSize   int64
	modID     string
	modStatAt time.Time

	// What the lines said the module verifies (mc=), per word of
	// trackedCaps: when a line last carried the word, and when a line last
	// did not -- a module from before the word, or a configuration from
	// before the field.
	capHave map[string]time.Time
	capLack map[string]time.Time
}

// New: a watch over the configuration rendered into dir().
func New(dir func() string) *Watch {
	return &Watch{
		dir: dir, seen: map[string]time.Time{}, modSeen: map[string]time.Time{},
		capHave: map[string]time.Time{}, capLack: map[string]time.Time{},
	}
}

// SetModulePath names the module file nginx loads (nginxconf.ModuleFilePath),
// read on every State; "" from it, or no function, and the module is not
// compared.
func (w *Watch) SetModulePath(f func() string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.modPath = f
	w.mu.Unlock()
}

// SawModule records the module id one access-log line carried, and what
// that module said it verifies.  An id of "" is a line with no mo= field: a
// module from before module ids, or a configuration rendered without the
// module, older than any module that has one.  caps is the line's mc= (words
// joined by commas); "" is a module that does not say, or a configuration
// from before the field -- either way a line that answers for nothing.
func (w *Watch) SawModule(id, caps string, at time.Time) {
	if w == nil {
		return
	}
	w.mu.Lock()
	prev, ok := w.modSeen[id]
	if !ok || at.Sub(prev) >= time.Second {
		w.modSeen[id] = at
		w.dirty = true
		if !ok && len(w.modSeen) > maxIDs {
			w.modSeen = pruneSeen(w.modSeen)
		}
	}
	for _, word := range trackedCaps {
		m := w.capLack
		if hasCap(caps, word) {
			m = w.capHave
		}
		if prev, ok := m[word]; !ok || at.Sub(prev) >= time.Second {
			m[word] = at
			w.dirty = true
		}
	}
	w.mu.Unlock()
}

// ModuleLacks: nginx's own lines say that a module in front of this daemon
// does not verify what word names, so a pass in that form would be refused
// and its holder challenged again.  False when the lines answer for the
// word, and false when there has been no line at all -- nothing has said
// so: a new install before its first request, or an install that sends the
// daemon no access log (forward-auth), where the daemon verifies its own
// passes.  CapLacks is the rule.
func (w *Watch) ModuleLacks(word string, now time.Time) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	have, lack := w.capHave[word], w.capLack[word]
	w.mu.Unlock()
	return CapLacks(have, lack, now)
}

// CapLacks is the rule on its own, so `unmask doctor` applies the same one
// to the state file: have is when a line last carried the word, lack when a
// line last did not.
//
// A line without the word is a module that does not verify it, and one such
// line is enough while it is the latest word from nginx.  Lines with and
// without it can alternate -- nginx upgraded in place runs its old and new
// workers side by side for as long as the old ones hold connections, and a
// daemon may be fed by more than one nginx -- so a line without the word
// counts for Grace after it was logged, whatever came since: the form is
// held back until every nginx that logs here has answered for it.
func CapLacks(have, lack time.Time, now time.Time) bool {
	if lack.IsZero() {
		return false
	}
	if have.IsZero() {
		return true
	}
	return !lack.Before(have) || now.Sub(lack) < Grace
}

// ModuleIDOnDisk: the identity of the module file at path, the way the
// module computes its own ($unmask_module_id: the first 16 hex digits of the
// file's SHA-256), and the file's mtime -- when it was placed.  "" when the
// file cannot be read.
func ModuleIDOnDisk(path string) (id string, placed time.Time) {
	f, err := os.Open(path)
	if err != nil {
		return "", time.Time{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", time.Time{}
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", time.Time{}
	}
	return hex.EncodeToString(h.Sum(nil))[:16], fi.ModTime()
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
	w.seen = pruneSeen(w.seen)
}

// pruneSeen drops the ids seen longest ago down to maxIDs.
func pruneSeen(seen map[string]time.Time) map[string]time.Time {
	for len(seen) > maxIDs {
		var oldID string
		var oldAt time.Time
		first := true
		for id, at := range seen {
			if first || at.Before(oldAt) {
				oldID, oldAt, first = id, at, false
			}
		}
		delete(seen, oldID)
	}
	return seen
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
	modPath := w.modPath
	modRecheck := modPath != nil && now.Sub(w.modStatAt) >= statEvery
	w.mu.Unlock()
	if recheck {
		w.refreshDisk(dir, now)
	}
	if modRecheck {
		w.refreshModule(modPath(), now)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Evaluate(w.diskID, w.diskWritten, w.seen)
	if w.modPath != nil {
		ms := Evaluate(w.modID, w.modMod, w.modSeen)
		st.ModuleCurrent, st.ModulePlaced = ms.Current, ms.Written
		st.ModulePending, st.ModuleRunning = ms.Pending, ms.Running
	}
	return st
}

// refreshModule hashes the module file again when it changed since the
// last look (or the path did).  Outside the lock, like refreshDisk.
func (w *Watch) refreshModule(path string, now time.Time) {
	var mod time.Time
	var size int64
	if path != "" {
		if fi, err := os.Stat(path); err == nil {
			mod, size = fi.ModTime(), fi.Size()
		}
	}
	w.mu.Lock()
	same := path == w.modFile && mod.Equal(w.modMod) && size == w.modSize
	w.mu.Unlock()
	if same {
		w.mu.Lock()
		w.modStatAt = now
		w.mu.Unlock()
		return
	}
	id, placed := "", time.Time{}
	if !mod.IsZero() {
		id, placed = ModuleIDOnDisk(path)
	}
	w.mu.Lock()
	w.modFile, w.modMod, w.modSize = path, mod, size
	w.modID = id
	if !placed.IsZero() {
		w.modMod = placed
	}
	w.modStatAt = now
	w.mu.Unlock()
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

	// The module, by the same rule.  ModuleCurrent: the id of the module
	// file at load_module's path ("" when none is wired or it cannot be
	// read -- nothing to compare), ModulePlaced its mtime.  ModulePending:
	// nginx logged another module's id after ModulePlaced plus Grace and
	// has not logged ModuleCurrent since -- it runs an older module, and
	// only a restart loads the new one.  ModuleRunning: the id the latest
	// of those lines carried ("" = a module from before module ids).
	ModuleCurrent string
	ModulePlaced  time.Time
	ModulePending bool
	ModuleRunning string
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
	Seen   map[string]time.Time `json:"seen"`
	Module map[string]time.Time `json:"module,omitempty"`
	// CapHave / CapLack: per word, when a line last carried it in mc= and
	// when a line last did not.  Absent from a file written before 0.1.58.
	CapHave map[string]time.Time `json:"cap_have,omitempty"`
	CapLack map[string]time.Time `json:"cap_lack,omitempty"`
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
	doc := stateDoc{
		Seen: make(map[string]time.Time, len(w.seen)), Module: make(map[string]time.Time, len(w.modSeen)),
		CapHave: make(map[string]time.Time, len(w.capHave)), CapLack: make(map[string]time.Time, len(w.capLack)),
	}
	for id, at := range w.seen {
		doc.Seen[id] = at.UTC()
	}
	for id, at := range w.modSeen {
		doc.Module[id] = at.UTC()
	}
	for word, at := range w.capHave {
		doc.CapHave[word] = at.UTC()
	}
	for word, at := range w.capLack {
		doc.CapLack[word] = at.UTC()
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
	doc, err := loadState(w.dir())
	if err != nil {
		return
	}
	w.mu.Lock()
	for id, at := range doc.Seen {
		if cur, ok := w.seen[id]; !ok || at.After(cur) {
			w.seen[id] = at
		}
	}
	if len(w.seen) > maxIDs {
		w.pruneLocked()
	}
	for id, at := range doc.Module {
		if cur, ok := w.modSeen[id]; !ok || at.After(cur) {
			w.modSeen[id] = at
		}
	}
	if len(w.modSeen) > maxIDs {
		w.modSeen = pruneSeen(w.modSeen)
	}
	for _, word := range trackedCaps {
		if at, ok := doc.CapHave[word]; ok && at.After(w.capHave[word]) {
			w.capHave[word] = at
		}
		if at, ok := doc.CapLack[word]; ok && at.After(w.capLack[word]) {
			w.capLack[word] = at
		}
	}
	w.mu.Unlock()
}

// LoadSeen reads the render ids of the state file in dir.
func LoadSeen(dir string) (map[string]time.Time, error) {
	doc, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	return doc.Seen, nil
}

// LoadModuleSeen reads the module ids of the state file in dir: when a line
// last carried each (mo=; "" = a line without the field, a module from
// before module ids or a configuration rendered without the module).
// `unmask doctor` reads it to say which module nginx has been running.
func LoadModuleSeen(dir string) (map[string]time.Time, error) {
	doc, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	return doc.Module, nil
}

// LoadModuleCaps reads from the state file in dir when a line last carried
// word in mc= (have) and when a line last did not (lack); CapLacks is what
// to make of the two.  `unmask doctor` reads it.
func LoadModuleCaps(dir, word string) (have, lack time.Time, err error) {
	doc, err := loadState(dir)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return doc.CapHave[word], doc.CapLack[word], nil
}

// loadState reads the state file in dir, with empty maps for what it lacks.
func loadState(dir string) (stateDoc, error) {
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		return stateDoc{}, err
	}
	var doc stateDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return stateDoc{}, err
	}
	if doc.Seen == nil {
		doc.Seen = map[string]time.Time{}
	}
	if doc.Module == nil {
		doc.Module = map[string]time.Time{}
	}
	// A file written before 0.1.58 says nothing of what the modules verify:
	// the lines it records came from a configuration that did not log it,
	// and answer for no word.  Read them as what they were -- lines without
	// each word, the latest of them -- so that a daemon started over such a
	// file holds a new form back from its first pass on, not from the first
	// line it hears.
	if doc.CapHave == nil && doc.CapLack == nil && len(doc.Module) > 0 {
		var latest time.Time
		for _, at := range doc.Module {
			if at.After(latest) {
				latest = at
			}
		}
		doc.CapLack = make(map[string]time.Time, len(trackedCaps))
		for _, word := range trackedCaps {
			doc.CapLack[word] = latest
		}
	}
	if doc.CapHave == nil {
		doc.CapHave = map[string]time.Time{}
	}
	if doc.CapLack == nil {
		doc.CapLack = map[string]time.Time{}
	}
	return doc, nil
}
