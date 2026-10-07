package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// Database compaction (internal/db/vacuum.go): the daemon's side.
//
// A compaction holds SQLite's write lock for as long as it runs -- tens of
// minutes on a large, fragmented file.  The daemon notices a run by its lock,
// whether it started the run itself (the button on the retention tab) or the
// run was typed into a shell, holds its writers back until the run ends
// (DB.HoldWritesForVacuum), and tells the run it has: the run waits for that
// before it takes the lock.  The challenge is served throughout; what the
// daemon would have written meanwhile -- events, access-log counters,
// automatic bans, audit rows -- waits in memory and is written when the run
// ends.
//
// The run is `unmask db-vacuum`, a process of its own, like a schema update
// (schema_update.go): its minutes of copying must not take the challenge
// down if it dies.

// vacuumRunner is the daemon's knowledge of the compaction runs.  The zero
// value is ready to use.
type vacuumRunner struct {
	// refreshMu makes one refresh at a time.
	refreshMu sync.Mutex

	mu sync.Mutex
	// rec: the last run's record as last read; hasRec false when there is
	// none.  running: a run holds the run lock (or, where the lock cannot be
	// looked at, its record says it is going and is young).
	rec     db.VacuumRecord
	hasRec  bool
	running bool
	// starting: the button's request is between its checks and the child's
	// start.  child: the run this daemon started, until its process has been
	// reaped.  A run is going when any of these or running says so.
	starting     bool
	child        *exec.Cmd
	childPID     int
	childStarted time.Time
	// startFailure: this daemon's last child ended in error without a record
	// of its own (it refused before taking the lock -- little to give back,
	// the disk short).  Shown until a record says otherwise.
	startFailure   string
	startFailureAt time.Time
	// wasGoing: a run was going at the last refresh.  lastEnded: the end of
	// the last run seen.  handedTo: the run the hand-over file names.
	wasGoing  bool
	lastEnded int64
	handedTo  int

	// The running run's progress, read at every refresh (two seconds apart
	// while one goes) whether or not anybody has the page open: step as last
	// read, at stepAt; stepRun the run it is of (its StartedAt).  stepSince /
	// stepFrom: when this daemon first saw the run at that step, and how far
	// it was then.  writeRate / writeTotal: the write-back's speed (bytes a
	// second) and size, once it has ended -- the checkpoint that follows
	// copies the same data (vacuumTimeLeft).
	step       db.VacuumStep
	stepOK     bool
	stepAt     time.Time
	stepRun    int64
	stepSince  time.Time
	stepFrom   int64
	writeRate  float64
	writeTotal int64
}

// observe takes a reading of the running run's progress.  v.mu held.
func (v *vacuumRunner) observe(rec db.VacuumRecord, s db.VacuumStep, now time.Time) {
	sameRun := v.stepOK && v.stepRun == rec.StartedAt
	if !sameRun || v.step.Phase != s.Phase {
		switch {
		case !sameRun:
			v.writeRate, v.writeTotal = 0, 0
		case v.step.Phase == "write":
			// The write-back has ended: its speed, from this daemon's
			// first sight of it to the last.
			if el := v.stepAt.Sub(v.stepSince).Seconds(); el >= 1 && v.step.Done > v.stepFrom {
				v.writeRate, v.writeTotal = float64(v.step.Done-v.stepFrom)/el, v.step.Total
			}
		}
		v.stepRun, v.stepSince, v.stepFrom = rec.StartedAt, now, s.Done
	}
	v.step, v.stepOK, v.stepAt = s, true, now
}

// timeLeft is how long the run's current step has left at the speed it has
// gone, read off the files rather than the estimate the run started with:
// the copy from the start of the run, the write-back from this daemon's
// first sight of it, the checkpoint at the write-back's speed (the same data
// again, in the same order).  ok is false until there is enough to go on --
// a minute and a few percent of the copy, twenty seconds of the write-back --
// and at the statistics, which no file measures.  v.mu held.
func (v *vacuumRunner) timeLeft(rec db.VacuumRecord, now time.Time) (time.Duration, bool) {
	if !v.stepOK || v.stepRun != rec.StartedAt {
		return 0, false
	}
	s := v.step
	var left float64 // seconds, as of stepAt
	switch s.Phase {
	case "copy":
		el := v.stepAt.Sub(time.Unix(rec.StartedAt, 0)).Seconds()
		if el < 60 || s.Total <= 0 || s.Done*30 < s.Total {
			return 0, false
		}
		left = float64(s.Total-s.Done) / (float64(s.Done) / el)
	case "write":
		el, done := v.stepAt.Sub(v.stepSince).Seconds(), s.Done-v.stepFrom
		if el < 20 || done <= 0 || s.Total <= 0 {
			return 0, false
		}
		left = float64(s.Total-s.Done) / (float64(done) / el)
	case db.VacuumStageCheckpoint:
		if v.writeRate <= 0 || v.writeTotal <= 0 {
			return 0, false
		}
		left = float64(v.writeTotal)/v.writeRate - v.stepAt.Sub(v.stepSince).Seconds()
	default:
		return 0, false
	}
	d := time.Duration(left*float64(time.Second)) - now.Sub(v.stepAt)
	if d <= 0 {
		// Slower than its speed so far: no figure rather than "soon".
		return 0, false
	}
	return d, true
}

func (v *vacuumRunner) going() bool { return v.running || v.child != nil || v.starting }

// VacuumGoing reports whether a compaction is going.
func (h *Handler) VacuumGoing() bool {
	h.vacuum.mu.Lock()
	defer h.vacuum.mu.Unlock()
	return h.vacuum.going()
}

// VacuumRefresh re-reads the run lock and the last run's record, sets the
// write hold to match, and hands over to a run that is waiting for it.
func (h *Handler) VacuumRefresh(ctx context.Context) {
	if h == nil || h.DB == nil || h.DB.Driver != db.DriverSQLite {
		return
	}
	v := &h.vacuum
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	held, known := h.DB.VacuumRunLockHeld()
	rec, ok, err := h.DB.LoadVacuum(ctx)
	if err != nil {
		// Unreadable now -- the run may have the database busy: the lock
		// says whether it is going, and the last record read stands.
		ok = false
	}
	running := held
	if !known {
		running = ok && h.DB.VacuumAlive(rec, time.Now())
	}
	// The run's progress, from its files (statfs and a stat).
	var step db.VacuumStep
	stepRead := false
	if running && ok && rec.State == db.VacuumRunning && rec.DiskFreeAtStart > 0 && h.DB.SQLitePath != "" {
		if free, err := db.DirFree(filepath.Dir(h.DB.SQLitePath)); err == nil {
			step, stepRead = db.VacuumProgress(rec, free, h.DB.WALSize()), true
		}
	}

	v.mu.Lock()
	if stepRead {
		v.observe(rec, step, time.Now())
	}
	if ok {
		v.rec, v.hasRec = rec, true
		if rec.EndedAt > 0 && !v.startFailureAt.IsZero() && time.Unix(rec.EndedAt, 0).After(v.startFailureAt) {
			v.startFailure, v.startFailureAt = "", time.Time{}
		}
	}
	v.running = running
	going := v.going()
	wasGoing := v.wasGoing
	v.wasGoing = going
	ended := ok && rec.EndedAt > 0 && rec.EndedAt != v.lastEnded
	if ok {
		v.lastEnded = rec.EndedAt
	}
	// Under mu, with the state it follows: a refresh that read the lock
	// before a child was started must not lift the hold vacuumStart has
	// just set.
	h.DB.HoldWritesForVacuum(going)
	// The run to hand over to: this daemon's child, or the one on record
	// (from a shell).  Its record comes a moment after its lock; until then
	// the writes are held and the hand-over waits for the next look.
	handTo := 0
	if going {
		switch {
		case v.childPID != 0:
			handTo = v.childPID
		case ok && rec.State == db.VacuumRunning && held:
			handTo = rec.PID
		}
	}
	if handTo != 0 && handTo != v.handedTo {
		if err := h.DB.WriteVacuumHeld(handTo); err != nil {
			log.Printf("db vacuum: could not tell the run (pid %d) the writes are held: %v", handTo, err)
		} else {
			v.handedTo = handTo
			log.Printf("db vacuum: a compaction is running (pid %d); writes are held until it ends", handTo)
		}
	}
	if !going {
		v.handedTo = 0
	}
	v.mu.Unlock()

	if !going && (wasGoing || ended) {
		// The run is over: what was kept meanwhile can be written.  The
		// event flusher and the ban manager see the hold lifted by
		// themselves; these two are written here.
		h.heldBeacons.reset()
		if h.UserRepo != nil {
			h.UserRepo.FlushHeld(ctx)
		}
	}
}

// RunVacuumWatch keeps VacuumRefresh current: a look at the run lock every two
// seconds -- an open and a flock, nothing read from the database -- so that a
// run typed into a shell is handed over to within moments, and a full refresh
// whenever a run is going or has just ended.
func (h *Handler) RunVacuumWatch(ctx context.Context) {
	if h == nil || h.DB == nil || h.DB.Driver != db.DriverSQLite {
		return
	}
	var last time.Time
	for {
		func() {
			defer safe.Recover("vacuum-watch")
			held, _ := h.DB.VacuumRunLockHeld()
			h.vacuum.mu.Lock()
			going := h.vacuum.going()
			h.vacuum.mu.Unlock()
			if held || going || time.Since(last) >= 5*time.Minute {
				rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				h.VacuumRefresh(rctx)
				last = time.Now()
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// VacuumView is what the admin UI shows about a compaction run, while one goes
// and for a day after: the retention tab's card in full, the top bar's small
// sign of it on every other page, and GET /admin/api/vacuum.
type VacuumView struct {
	// State: "running", "done", "failed" or "cancelled".  There is no view
	// (nil) when there is nothing to say.
	State string `json:"state"`
	// StartedAt / EndedAt: unix seconds; Now the server's clock, so the page
	// counts elapsed time without trusting the browser's.
	StartedAt int64 `json:"started_at,omitempty"`
	EndedAt   int64 `json:"ended_at,omitempty"`
	Now       int64 `json:"now"`
	// Est: the estimate the run started with, in the reader's language.
	// Took: how long an ended run took.
	Est  string `json:"est,omitempty"`
	Took string `json:"took,omitempty"`
	By   string `json:"by,omitempty"`
	Host string `json:"host,omitempty"`
	Err  string `json:"err,omitempty"`
	// Phase: the step a running run is on -- "copy" and "write", the two
	// VACUUM takes, read from its files, then db.VacuumStageCheckpoint and
	// db.VacuumStageStats -- of Steps (3, or 4 with the statistics);
	// Progress the percent of that step, -1 where no file shows it.
	// StepText says it in the reader's words ("Copying 52%"), PillText the
	// top bar's way ("Compacting DB: copy 52%"); TimeLeft the time the step
	// has left at the speed it has gone, "" until that can be told.
	Phase    string `json:"phase,omitempty"`
	Steps    int    `json:"steps,omitempty"`
	Progress int    `json:"progress"`
	StepText string `json:"step_text,omitempty"`
	PillText string `json:"pill_text,omitempty"`
	TimeLeft string `json:"time_left,omitempty"`
	// Held: the events the daemon keeps meanwhile.  HeldText says so with
	// the limit past which the oldest go and how long the rest lasts at the
	// rate they come; HeldNear: the count is close to that limit.
	Held     int    `json:"held"`
	HeldText string `json:"held_text,omitempty"`
	HeldNear bool   `json:"held_near,omitempty"`
	// FileBefore / FileAfter: the file's size before, and after a done run.
	FileBefore string `json:"file_before,omitempty"`
	FileAfter  string `json:"file_after,omitempty"`
	// Cancellable: this session may stop the run -- a superadmin, and the
	// run is this daemon's own or a `db-vacuum` from a shell that this
	// daemon may signal (vacuumSignalable).  CanCancel: and its step allows
	// it -- not the checkpoint, which a stop neither undoes nor shortens.
	// CancelNote: what stopping it now does; StopHint: how else it is
	// stopped, where this session cannot.  StopNote: the two as the card
	// puts them by the button.
	Cancellable bool   `json:"cancellable"`
	CanCancel   bool   `json:"can_cancel"`
	CancelNote  string `json:"cancel_note,omitempty"`
	StopHint    string `json:"stop_hint,omitempty"`
	StopNote    string `json:"stop_note,omitempty"`
	// Bars: the steps as the card first draws them; the page redraws them
	// from Phase and Progress.
	Bars []StepBar `json:"-"`
}

// StepBar is one step of a running maintenance run as the page draws it (the
// compaction card, the schema update notice): its share filled, whether it is
// the step going, and whether that step's progress is unknown (the bar is
// drawn full and moving).
type StepBar struct {
	Phase         string
	Fill          int
	Current, Busy bool
}

// stepBars draws the steps of a run on step phase: the ones before it done,
// it filled to pct (-1: unknown), the ones after it empty.
func stepBars(phases []string, phase string, pct int) []StepBar {
	bars := make([]StepBar, 0, len(phases))
	passed := false
	for _, p := range phases {
		b := StepBar{Phase: p}
		switch {
		case p == phase:
			b.Current, passed = true, true
			b.Fill = pct
			if pct < 0 {
				b.Fill, b.Busy = 100, true
			}
		case !passed:
			b.Fill = 100
		}
		bars = append(bars, b)
	}
	return bars
}

// vacuumShownFor is how long an ended run stays on the page.
const vacuumShownFor = 24 * time.Hour

// vacuumView builds the view for a session of the given role, in lang.  nil
// when there is nothing to show.
func (h *Handler) vacuumView(role string, lang i18n.Lang) *VacuumView {
	if h == nil || h.DB == nil || h.DB.Driver != db.DriverSQLite {
		return nil
	}
	now := time.Now()
	v := &h.vacuum
	v.mu.Lock()
	rec, hasRec, running := v.rec, v.hasRec, v.running
	ours := v.child != nil || v.starting
	childPID, childStarted := v.childPID, v.childStarted
	failure, failureAt := v.startFailure, v.startFailureAt
	step, stepOK := v.step, v.stepOK && v.stepRun == rec.StartedAt
	left, leftOK := v.timeLeft(rec, now)
	v.mu.Unlock()

	super := roleAtLeast(role, user.RoleSuperadmin)
	out := &VacuumView{Now: now.Unix()}
	fromRecord := func() {
		out.StartedAt, out.By, out.Host = rec.StartedAt, rec.By, rec.Host
		out.Est = estimateText(lang, time.Duration(rec.EstLowSec)*time.Second, time.Duration(rec.EstHighSec)*time.Second)
		if rec.FileBefore > 0 {
			out.FileBefore = humanBytes(rec.FileBefore)
		}
	}
	switch {
	case running || ours:
		out.State = "running"
		out.Phase, out.Steps = "copy", 3
		onRecord := hasRec && rec.State == db.VacuumRunning && (childPID == 0 || rec.PID == childPID)
		if onRecord {
			fromRecord()
			if stepOK {
				out.Phase, out.Progress = step.Phase, int(step.Frac()*100)
				if step.Frac() < 0 {
					out.Progress = -1
				}
			}
			// The statistics step: announced by the run, or under way.
			if rec.Stats || out.Phase == db.VacuumStageStats {
				out.Steps = 4
			}
			if leftOK {
				out.TimeLeft = i18n.Tf(lang, "vacuum.left_"+out.Phase, aboutText(lang, left))
			}
		} else {
			out.StartedAt = now.Unix()
			if !childStarted.IsZero() {
				out.StartedAt = childStarted.Unix()
			}
		}
		out.StepText, out.PillText = vacuumStepText(lang, out.Phase, out.Progress)
		phases := []string{"copy", "write", db.VacuumStageCheckpoint}
		if out.Steps == 4 {
			phases = append(phases, db.VacuumStageStats)
		}
		out.Bars = stepBars(phases, out.Phase, out.Progress)
		out.Held = int(events.HeldEvents())
		out.HeldText, out.HeldNear = heldText(lang, out.Held, db.HeldEventsLimit(), now.Sub(time.Unix(out.StartedAt, 0)))
		shell := childPID == 0 && onRecord && running && super && runSignalable(rec.PID, "db-vacuum")
		out.Cancellable = super && (childPID != 0 || shell)
		out.CanCancel = out.Cancellable && out.Phase != db.VacuumStageCheckpoint
		switch out.Phase {
		case db.VacuumStageCheckpoint:
			out.CancelNote = i18n.T(lang, "vacuum.cancel_note_checkpoint")
		case db.VacuumStageStats:
			out.CancelNote = i18n.T(lang, "vacuum.cancel_note_stats")
		default:
			out.CancelNote = i18n.T(lang, "vacuum.cancel_note")
		}
		switch {
		case out.Cancellable || out.Phase == db.VacuumStageCheckpoint:
		case !super:
			out.StopHint = i18n.T(lang, "vacuum.stop_hint_role")
		case onRecord && rec.PID > 0:
			out.StopHint = i18n.Tf(lang, "vacuum.stop_hint_shell", rec.PID)
		}
		out.StopNote = out.CancelNote
		if out.StopHint != "" {
			sep := " "
			if lang == i18n.LangJA {
				sep = "" // sentences run on after "。"
			}
			out.StopNote = out.StopHint + sep + out.CancelNote
		}
	case failure != "" && now.Sub(failureAt) < vacuumShownFor:
		out.State, out.Err, out.EndedAt = "failed", failure, failureAt.Unix()
	case hasRec && rec.EndedAt > 0 && now.Sub(time.Unix(rec.EndedAt, 0)) < vacuumShownFor:
		fromRecord()
		out.EndedAt, out.Took = rec.EndedAt, durationText(lang, int(rec.Seconds+0.5))
		switch rec.State {
		case db.VacuumDone:
			out.State = "done"
			out.FileAfter = humanBytes(rec.FileAfter)
		case db.VacuumCancelled:
			out.State = "cancelled"
		default:
			out.State, out.Err = "failed", rec.Err
		}
	case hasRec && rec.State == db.VacuumRunning:
		// Marked running and its lock is free: it was killed.
		fromRecord()
		out.State, out.Err, out.EndedAt = "failed", i18n.T(lang, "vacuum.err_interrupted"), rec.StartedAt
	default:
		return nil
	}
	return out
}

// VacuumCard is the retention tab's compaction card: what a run would give
// back and need, and how the last one went.
type VacuumCard struct {
	// Show: the database is SQLite (MariaDB has nothing to compact).
	Show bool
	// PlanErr: the plan could not be worked out (the error, shortened).
	PlanErr string
	Plan    db.VacuumPlan
	// The plan's figures in the reader's words.
	File, Live, Reclaim, DiskNeed, DiskFree, HeldBytes, CountersBytes string
	ReclaimPct                                                        int
	Est                                                               string
	EventsPerHour, HeldEvents, HeldLimit                              string
	// HeldUpTo: the high end of the estimate, which HeldEvents is the event
	// rate over -- an estimate, not a bound: a run may take longer.
	// HeldLasts: how long the daemon can hold events at that rate before the
	// oldest go ("" with no events lately).  HoldMem: the memory the hold
	// takes over HeldUpTo -- the events, and the access-log counters when
	// the access-log integration is on (CountersOn); without it there are
	// no counters to keep.
	HeldUpTo, HeldLasts, HoldMem string
	CountersOn                   bool
	// CanRun: this session may start a run now (a superadmin, nothing going,
	// and the plan says it is worth it and has room).
	CanRun bool
	// Going: a compaction or a schema update is going; Blocked names why a
	// superadmin cannot start one now ("" when they can).
	Going   bool
	Blocked string
	// Last: the run going, or the last one when it ended in the last day.
	// Running: it is going -- the card shows its progress where the button
	// was.
	Last    *VacuumView
	Running bool
}

// vacuumCard builds the retention tab's card.
func (h *Handler) vacuumCard(ctx context.Context, role string, lang i18n.Lang) VacuumCard {
	var c VacuumCard
	if h == nil || h.DB == nil || h.DB.Driver != db.DriverSQLite {
		return c
	}
	c.Show = true
	h.VacuumRefresh(ctx)
	p, err := h.DB.PlanVacuum(ctx)
	if err != nil {
		c.PlanErr = err.Error()
	} else {
		c.Plan = p
		c.File, c.Live, c.Reclaim = sizeText(p.FileBytes), sizeText(p.LiveBytes), sizeText(p.Reclaim)
		c.DiskNeed, c.HeldBytes, c.CountersBytes = sizeText(p.DiskNeed), sizeText(p.HeldBytes), sizeText(p.CountersBytes)
		if p.DiskFree >= 0 {
			c.DiskFree = humanBytes(p.DiskFree)
		}
		if p.FileBytes > 0 {
			c.ReclaimPct = int(p.Reclaim * 100 / p.FileBytes)
		}
		c.Est = estimateText(lang, p.EstLow, p.EstHigh)
		c.EventsPerHour, c.HeldEvents, c.HeldLimit = groupDigits(p.EventsPerHour), groupDigits(p.HeldEvents), groupDigits(p.HeldLimit)
		c.HeldUpTo = upToText(lang, p.EstHigh)
		if p.EventsPerHour > 0 {
			c.HeldLasts = aboutText(lang, time.Duration(float64(p.HeldLimit)/float64(p.EventsPerHour)*float64(time.Hour)))
		}
		mem := p.HeldBytes
		if c.CountersOn = h.cfg().NginxLog.Enabled; c.CountersOn {
			mem += p.CountersBytes
		}
		c.HoldMem = sizeText(mem)
	}
	c.Last = h.vacuumView(role, lang)
	c.Running = c.Last != nil && c.Last.State == "running"
	_, schemaGoing := h.SchemaWaiting()
	c.Going = h.VacuumGoing() || schemaGoing
	switch {
	case !roleAtLeast(role, user.RoleSuperadmin):
		c.Blocked = i18n.T(lang, "vacuum.needs_superadmin")
	case c.Going:
		c.Blocked = i18n.T(lang, "vacuum.blocked_going")
	case c.PlanErr != "":
		c.Blocked = c.PlanErr
	case c.Plan.DiskShort():
		c.Blocked = i18n.Tf(lang, "vacuum.blocked_disk", c.DiskNeed, c.DiskFree)
	case !c.Plan.Worth():
		c.Blocked = i18n.T(lang, "vacuum.blocked_little")
	case c.Plan.HeldOver():
		c.Blocked = i18n.Tf(lang, "vacuum.blocked_held", c.HeldEvents, c.HeldLimit)
	default:
		c.CanRun = true
	}
	return c
}

// AdminVacuumStatus: GET /admin/api/vacuum -- the view, or {"state":"none"}.
func (h *Handler) AdminVacuumStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.VacuumRefresh(ctx)
	role := ""
	if pay := SessionFromContext(r); pay != nil {
		role = pay.Role
	}
	v := h.vacuumView(role, i18n.Resolve(r))
	if v == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "none", "now": time.Now().Unix()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// AdminVacuumRun: POST /admin/api/vacuum/run (superadmin).
func (h *Handler) AdminVacuumRun(w http.ResponseWriter, r *http.Request) {
	pay := SessionFromContext(r)
	by := "admin"
	if pay != nil && h.UserRepo != nil {
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil && u != nil {
			by = u.Username
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.VacuumRefresh(ctx)
	h.SchemaRefresh(ctx)
	if err := h.vacuumReserve(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	started := false
	defer func() {
		if !started {
			h.vacuum.mu.Lock()
			h.vacuum.starting = false
			h.vacuum.mu.Unlock()
		}
	}()
	// The audit row before the start: from then on the write lock may be
	// the run's.
	if h.UserRepo != nil && pay != nil {
		h.UserRepo.Record(r.Context(), pay.UserID, by, "db.vacuum", "", "")
	}
	started = true // vacuumStart takes the claim over, whatever it returns
	if err := h.vacuumStart(by); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// AdminVacuumCancel: POST /admin/api/vacuum/cancel (superadmin).
func (h *Handler) AdminVacuumCancel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.VacuumRefresh(ctx)
	by, err := h.vacuumCancel()
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	// Held with the other writes until the run has ended.  The target is
	// who started the run: a superadmin may stop a run typed into a shell.
	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		name := "admin"
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil && u != nil {
			name = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, name, "db.vacuum.cancel", by, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

var (
	errVacuumNothing   = errors.New("no compaction is running")
	errVacuumNotOurs   = errors.New("the running compaction cannot be stopped from here (it runs as another user, or is not a db-vacuum process of this host); stop it where it runs: Ctrl-C, or kill -INT with its process id")
	errVacuumCommitted = errors.New("the compaction is committed and is being written into the database file; that cannot be stopped")
)

// vacuumReserve claims the start of a run: no compaction and no schema update
// may be going -- both hold the same write lock.  The run checks again, by
// their locks.
func (h *Handler) vacuumReserve() error {
	if _, schemaGoing := h.SchemaWaiting(); schemaGoing {
		return db.ErrSchemaUpdateRunning
	}
	v := &h.vacuum
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.going() {
		return db.ErrVacuumRunning
	}
	v.starting = true
	return nil
}

// vacuumStart starts the reserved run as a child process.
func (h *Handler) vacuumStart(by string) error {
	v := &h.vacuum
	v.mu.Lock()
	defer v.mu.Unlock()
	v.starting = false
	cmd, err := h.vacuumCommand(by)
	if err != nil {
		return err
	}
	out, _ := cmd.Stdout.(*logLines)
	// Held before the run can take the lock, and said so the moment its
	// process id is known: the run waits for exactly that.
	h.DB.HoldWritesForVacuum(true)
	if err := cmd.Start(); err != nil {
		h.DB.HoldWritesForVacuum(false)
		return fmt.Errorf("start the compaction: %w", err)
	}
	pid := cmd.Process.Pid
	v.child, v.childPID, v.childStarted = cmd, pid, time.Now()
	v.startFailure, v.startFailureAt = "", time.Time{}
	if err := h.DB.WriteVacuumHeld(pid); err != nil {
		log.Printf("db vacuum: could not tell the run (pid %d) the writes are held: %v", pid, err)
	} else {
		v.handedTo = pid
	}
	log.Printf("db vacuum: started by %s (pid %d)", LogSafe(by), pid)
	go func() {
		defer safe.Recover("db-vacuum-wait")
		err := cmd.Wait()
		v.mu.Lock()
		v.child = nil
		v.mu.Unlock()
		if err != nil {
			log.Printf("db vacuum: ended with %v", err)
		} else {
			log.Printf("db vacuum: finished")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.VacuumRefresh(ctx)
		v.mu.Lock()
		if err != nil && !(v.hasRec && v.rec.PID == pid) {
			// It ended in error before it recorded itself: its own
			// last words say why.
			msg := err.Error()
			if out != nil {
				if tail := out.tail(); tail != "" {
					msg = tail
				}
			}
			v.startFailure, v.startFailureAt = msg, time.Now()
		}
		v.childPID, v.childStarted = 0, time.Time{}
		v.mu.Unlock()
		// With the child gone and its record read: lift the hold if this
		// was the last thing holding it.
		h.VacuumRefresh(ctx)
	}()
	return nil
}

// vacuumCancel stops the run going -- the one this daemon started, or one
// typed into a shell that it may signal (runSignalable) -- with SIGTERM,
// which `unmask db-vacuum` takes as Ctrl-C: SQLite rolls VACUUM back and the
// run records itself as cancelled.  At the statistics, only they are given
// up.  by: who started the run, as its record says.
func (h *Handler) vacuumCancel() (by string, err error) {
	v := &h.vacuum
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.hasRec && v.rec.State == db.VacuumRunning {
		by = v.rec.By
		if v.stepOK && v.stepRun == v.rec.StartedAt && v.step.Phase == db.VacuumStageCheckpoint {
			return by, errVacuumCommitted
		}
	}
	if v.child != nil && v.child.Process != nil {
		log.Printf("db vacuum: cancel requested (pid %d)", v.child.Process.Pid)
		return by, v.child.Process.Signal(syscall.SIGTERM)
	}
	if !v.running {
		return "", errVacuumNothing
	}
	pid := 0
	if v.hasRec && v.rec.State == db.VacuumRunning {
		pid = v.rec.PID
	}
	if !runSignalable(pid, "db-vacuum") {
		return by, errVacuumNotOurs
	}
	log.Printf("db vacuum: cancel requested for the run started from a shell (pid %d)", pid)
	return by, syscall.Kill(pid, syscall.SIGTERM)
}

// runSignalable reports whether pid is a maintenance run this daemon may
// stop: a process of this host running the unmask subcommand sub
// ("db-vacuum", "migrate") -- the record's process id is checked, not
// trusted -- that a signal from the daemon's user reaches.  A run typed in
// as root has dropped to the daemon's user (privdrop.go), so it does; one
// run with UNMASK_NO_PRIVDROP does not.
func runSignalable(pid int, sub string) bool {
	if pid <= 0 || pid == os.Getpid() {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	for _, arg := range strings.Split(string(b), "\x00") {
		if arg == sub {
			return syscall.Kill(pid, 0) == nil
		}
	}
	return false
}

// StopVacuumRun stops the run this daemon started, if one is going, and waits
// for it to end, until ctx is done.  For the daemon's shutdown: the run holds
// the write lock the last flush of the kept events needs.  Stopped, it rolls
// back and records itself as cancelled.
func (h *Handler) StopVacuumRun(ctx context.Context) {
	if h == nil {
		return
	}
	v := &h.vacuum
	v.mu.Lock()
	child := v.child
	v.mu.Unlock()
	if child == nil || child.Process == nil {
		return
	}
	log.Printf("db vacuum: stopping the run this daemon started (pid %d) before shutting down", child.Process.Pid)
	_ = child.Process.Signal(syscall.SIGTERM)
	for {
		v.mu.Lock()
		gone := v.child == nil
		v.mu.Unlock()
		if gone {
			return
		}
		select {
		case <-ctx.Done():
			log.Printf("db vacuum: the run did not stop in time; leaving it")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// vacuumCommand builds the child: this binary, `db-vacuum`.
func (h *Handler) vacuumCommand(by string) (*exec.Cmd, error) {
	if h.VacuumCommand != nil {
		return h.VacuumCommand(by)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find this binary: %w", err)
	}
	args := []string{"db-vacuum", "-by", by}
	if h.ConfigPath != "" {
		args = append(args, "-config", h.ConfigPath)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = os.Environ()
	out := &logLines{prefix: "db vacuum: "}
	cmd.Stdout, cmd.Stderr = out, out
	return cmd, nil
}

// vacuumStepText words a running run's step: in full for the card
// ("Copying 52%") and short for the top bar ("Compacting DB: copy 52%").
// pct is -1 at a step no file measures.
func vacuumStepText(lang i18n.Lang, phase string, pct int) (step, pill string) {
	name := i18n.T(lang, "vacuum.step_"+phase)
	switch phase {
	case "copy", "write":
		pct = max(pct, 0)
		return i18n.Tf(lang, "vacuum.phase_"+phase, pct), i18n.Tf(lang, "vacuum.pill_running", fmt.Sprintf("%s %d%%", name, pct))
	}
	return i18n.T(lang, "vacuum.phase_"+phase), i18n.Tf(lang, "vacuum.pill_running", name)
}

// heldText words the events the daemon keeps during a run -- a compaction or
// a schema update -- how many, the
// limit past which the oldest go, and -- once the run has gone a minute --
// how long the rest lasts at the rate they have come.  near: within a tenth
// of the limit, which the flusher trims back to when it is passed.
func heldText(lang i18n.Lang, held, limit int, el time.Duration) (string, bool) {
	n, l := groupDigits(int64(held)), groupDigits(int64(limit))
	if limit > 0 && held*10 >= limit*9 {
		return i18n.Tf(lang, "vacuum.held_near", n, l), true
	}
	if held > 0 && el >= time.Minute && limit > held {
		lasts := time.Duration(float64(limit-held) / float64(held) * float64(el))
		return i18n.Tf(lang, "vacuum.held_now_lasts", n, l, aboutText(lang, lasts)), false
	}
	return i18n.Tf(lang, "vacuum.held_now", n, l), false
}

// aboutText words a projected time, "about" included: to the minute under an
// hour and a half, to five minutes under ten hours, to the hour under two
// days, and in days above.
func aboutText(lang i18n.Lang, d time.Duration) string {
	ja := lang == i18n.LangJA
	switch {
	case d < time.Minute:
		if ja {
			return "1 分未満"
		}
		return "under a minute"
	case d < 90*time.Minute:
		m := int((d + 30*time.Second) / time.Minute)
		if ja {
			return fmt.Sprintf("約 %d 分", m)
		}
		return fmt.Sprintf("about %d min", m)
	case d < 10*time.Hour:
		m := int((d+150*time.Second)/(5*time.Minute)) * 5
		h, m := m/60, m%60
		switch {
		case m == 0 && ja:
			return fmt.Sprintf("約 %d 時間", h)
		case m == 0:
			return fmt.Sprintf("about %d h", h)
		case ja:
			return fmt.Sprintf("約 %d 時間 %d 分", h, m)
		}
		return fmt.Sprintf("about %d h %d min", h, m)
	}
	if d < 48*time.Hour {
		h := int((d + 30*time.Minute) / time.Hour)
		if ja {
			return fmt.Sprintf("約 %d 時間", h)
		}
		return fmt.Sprintf("about %d h", h)
	}
	days := int((d + 12*time.Hour) / (24 * time.Hour))
	if ja {
		return fmt.Sprintf("約 %d 日", days)
	}
	return fmt.Sprintf("about %d days", days)
}

// groupDigits: 1234567 -> "1,234,567".
func groupDigits(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// upToText words the high end of an estimate the way its range does
// (db.EstimateRange rounds up to 10 s below 90 s, and to the minute above),
// without the "about": the card gives the events held as the event rate over
// it.
func upToText(lang i18n.Lang, d time.Duration) string {
	if d < 90*time.Second {
		s := int((d+10*time.Second-1)/(10*time.Second)) * 10
		if s < 10 {
			s = 10
		}
		if lang == i18n.LangJA {
			return fmt.Sprintf("%d 秒", s)
		}
		return fmt.Sprintf("%d s", s)
	}
	m := int((d + time.Minute - 1) / time.Minute)
	if lang == i18n.LangJA {
		return fmt.Sprintf("%d 分", m)
	}
	return fmt.Sprintf("%d min", m)
}

// sizeText is humanBytes that says "0 B" for nothing rather than leaving a
// blank: a figure the card states, not one that may be unknown.
func sizeText(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	return humanBytes(n)
}
