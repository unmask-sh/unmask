package handlers

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// Schema updates the daemon left for the operator.
//
// A migration that only builds an index is not applied at startup when the
// build is expected to take long (internal/db/migrator.go): the daemon would
// be gone for that time, unannounced.  This file is the daemon's side of
// what happens instead -- it knows what is waiting, shows it on every admin
// page, starts the update when an administrator asks for it, and keeps its own
// writers out of the way while it runs.
//
// The update itself is `unmask migrate`, run as a child process: the same code
// an operator runs from a shell, and a process of its own so that minutes of
// sorting cannot take the challenge down with them.  The two sides meet in one
// row of unmask_maint_state (db.SchemaUpdateRecord), which is also how a run
// started from a shell shows up here.

// schemaUpdater is the daemon's knowledge of the schema updates: what is
// waiting, and the run in progress.  The zero value is ready to use.
type schemaUpdater struct {
	mu sync.Mutex
	// waiting: the migrations a start of this daemon leaves for the operator.
	waiting []db.PendingMigration
	// rec: the last run's record as last read; hasRec false when there is none.
	rec    db.SchemaUpdateRecord
	hasRec bool
	// running: the record describes a run that is going (rec.Alive at the
	// last look).
	running bool
	// child: the run this daemon started, from the moment it is started until
	// its process has been reaped; childStarted is when.  A run is going
	// when either this or running says so: the child is there before its
	// record is, and for a moment after the record says it ended.
	child        *exec.Cmd
	childStarted time.Time
	// wasGoing: a run was in progress at the last refresh.  The refresh that
	// finds it over is the one that re-reads the index list.
	wasGoing bool
}

// going reports whether a run is in progress.  Call with mu held.
func (u *schemaUpdater) going() bool { return u.running || u.child != nil }

// SchemaUpdateView is what the admin UI shows about the schema updates.  The
// notice template renders it, and GET /admin/api/schema-update returns it.
type SchemaUpdateView struct {
	// State: "pending", "running", "done" or "failed".  There is no view at
	// all (nil) when there is nothing to say.
	State string `json:"state"`
	// Count is how many migrations wait; Est how long applying them is
	// expected to take, in the reader's language.
	Count int    `json:"count"`
	Est   string `json:"est,omitempty"`
	// CanRun / CanCancel: this session may start / stop the run.  Starting
	// takes a superadmin; stopping also takes the run to be this daemon's.
	CanRun    bool `json:"can_run"`
	CanCancel bool `json:"can_cancel"`
	// HoldsWrites: the run keeps every other write out for as long as it
	// takes (SQLite, which has one writer), so the notice has to say what
	// waits.  False where the index is built online (MariaDB) and nothing
	// does.
	HoldsWrites bool `json:"holds_writes"`
	// StartedAt / EndedAt: unix seconds.  Seconds is how long an ended run
	// took, and Took the same in the reader's language.
	StartedAt int64  `json:"started_at,omitempty"`
	EndedAt   int64  `json:"ended_at,omitempty"`
	Seconds   int    `json:"seconds,omitempty"`
	Took      string `json:"took,omitempty"`
	// By / Host: who started the run, and where.
	By   string `json:"by,omitempty"`
	Host string `json:"host,omitempty"`
	// Err: why the last run failed.  Cancelled: the last run was stopped (the
	// update is pending again).
	Err       string `json:"err,omitempty"`
	Cancelled bool   `json:"cancelled,omitempty"`
	// Now is the server's clock, so the page counts elapsed time from
	// StartedAt without trusting the browser's.
	Now int64 `json:"now"`
}

// doneShownFor is how long a finished run stays on the page.
const doneShownFor = 24 * time.Hour

// SchemaRefresh re-reads what is waiting and the last run's record, and sets
// the database's write hold to match.  Cheap: the list of applied versions,
// two seeks for the table's size and one row by key.
func (h *Handler) SchemaRefresh(ctx context.Context) {
	if h == nil || h.DB == nil {
		return
	}
	pending, err := db.PendingMigrations(h.DB)
	if err != nil {
		// A database that cannot be read now (locked, restarting) says
		// nothing about what is waiting: keep the last answer.
		return
	}
	waiting := db.LeftForTheOperator(pending, h.cfg().DB.SchemaUpdateDeferOver())
	rec, ok, err := h.DB.LoadSchemaUpdate(ctx)
	if err != nil {
		return
	}
	running := ok && rec.Alive(h.HostID, time.Now())

	u := &h.schema
	u.mu.Lock()
	u.waiting, u.rec, u.hasRec, u.running = waiting, rec, ok, running
	going := u.going()
	wasGoing := u.wasGoing
	u.wasGoing = going
	u.mu.Unlock()

	h.DB.HoldWrites(going && h.DB.SchemaUpdateHoldsWrites())
	if wasGoing && !going {
		// The run ended (here or in a shell): the index it built is there
		// now, and the hints that name it can come back.
		if err := h.DB.RefreshIndexes(ctx); err != nil {
			log.Printf("schema update: re-reading the index list: %v", err)
		}
	}
}

// RunSchemaWatch keeps SchemaRefresh current: every two seconds while an
// update waits or runs -- a run started from a shell has to be noticed, and
// the page shows its progress -- and rarely otherwise.
func (h *Handler) RunSchemaWatch(ctx context.Context) {
	defer safe.Recover("schema-watch")
	for {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		h.SchemaRefresh(rctx)
		cancel()
		wait := 5 * time.Minute
		h.schema.mu.Lock()
		if len(h.schema.waiting) > 0 || h.schema.going() {
			// Short: until a run started from a shell is noticed, the
			// daemon's writes go against its lock.
			wait = 2 * time.Second
		}
		h.schema.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// SchemaWaiting is how many schema updates wait for the operator, and
// whether one is running.  For /metrics and the startup log.
func (h *Handler) SchemaWaiting() (waiting int, running bool) {
	h.schema.mu.Lock()
	defer h.schema.mu.Unlock()
	return len(h.schema.waiting), h.schema.going()
}

// schemaView builds the view for a session of the given role, in lang.
// nil when there is nothing to show.
func (h *Handler) schemaView(role string, lang i18n.Lang) *SchemaUpdateView {
	if h == nil {
		return nil
	}
	u := &h.schema
	u.mu.Lock()
	waiting := append([]db.PendingMigration(nil), u.waiting...)
	rec, hasRec, running := u.rec, u.hasRec, u.running
	ours := u.child != nil
	startedAt := u.childStarted
	u.mu.Unlock()

	super := roleAtLeast(role, user.RoleSuperadmin)
	now := time.Now()
	v := &SchemaUpdateView{Now: now.Unix(), Count: len(waiting), HoldsWrites: h.DB.SchemaUpdateHoldsWrites()}
	var low, high time.Duration
	for _, m := range waiting {
		low, high = low+m.EstLow, high+m.EstHigh
	}
	v.Est = estimateText(lang, low, high)

	switch {
	case running:
		v.State = "running"
		v.StartedAt, v.By, v.Host = rec.StartedAt, rec.By, rec.Host
		v.Count = len(rec.Items)
		v.Est = estimateText(lang, time.Duration(rec.EstLowSec)*time.Second, time.Duration(rec.EstHighSec)*time.Second)
		v.CanCancel = super && ours
	case ours:
		// This daemon's run, and no record of it being under way: it was
		// started a moment ago, or is about to be reaped.
		v.State = "running"
		v.StartedAt = startedAt.Unix()
		v.CanCancel = super
	case len(waiting) > 0:
		v.State = "pending"
		v.CanRun = super
		if hasRec && rec.EndedAt > 0 && now.Sub(time.Unix(rec.EndedAt, 0)) < doneShownFor {
			switch rec.State {
			case db.SchemaUpdateFailed:
				v.State, v.Err, v.EndedAt = "failed", rec.Err, rec.EndedAt
			case db.SchemaUpdateCancelled:
				v.Cancelled = true
			}
		} else if hasRec && rec.State == db.SchemaUpdateRunning {
			// Marked running and its process is gone: it was killed.
			v.State, v.Err, v.EndedAt = "failed", i18n.T(lang, "schema_update.err_interrupted"), rec.StartedAt
		}
	case hasRec && rec.State == db.SchemaUpdateDone && now.Sub(time.Unix(rec.EndedAt, 0)) < doneShownFor &&
		(rec.Seconds >= 1 || rec.By != db.SchemaUpdateByCLI):
		// A run from a shell that took no time at all is not news: that is
		// a new install's first migrate.  One started with the button is
		// always answered, however quick it was -- the notice the
		// administrator pressed it on must not just vanish.
		v.State = "done"
		v.EndedAt, v.Seconds, v.By, v.Host = rec.EndedAt, int(rec.Seconds+0.5), rec.By, rec.Host
		v.Took = durationText(lang, v.Seconds)
		v.Count = len(rec.Items)
	default:
		return nil
	}
	return v
}

// estimateText words a build-time estimate in the reader's language; the
// English is db.EstimateRange.
func estimateText(lang i18n.Lang, low, high time.Duration) string {
	en := db.EstimateRange(low, high)
	if lang != i18n.LangJA {
		return en
	}
	// "under 10 s" / "about 30 s" / "20-50 s" / "about 4 min" / "4-10 min"
	r := strings.NewReplacer("under ", "", "about ", "", " s", " 秒", " min", " 分", "-", "〜")
	switch {
	case en == "no time":
		return "ほぼ 0 秒"
	case strings.HasPrefix(en, "under "):
		return r.Replace(en) + "未満"
	case strings.HasPrefix(en, "about "):
		return "約 " + r.Replace(en)
	}
	return r.Replace(en)
}

// durationText words a number of seconds: "under 1 s", "52 s", "3 min 52 s".
func durationText(lang i18n.Lang, sec int) string {
	m, s := sec/60, sec%60
	if sec <= 0 {
		if lang == i18n.LangJA {
			return "1 秒未満"
		}
		return "under 1 s"
	}
	if lang == i18n.LangJA {
		if m == 0 {
			return fmt.Sprintf("%d 秒", s)
		}
		return fmt.Sprintf("%d 分 %d 秒", m, s)
	}
	if m == 0 {
		return fmt.Sprintf("%d s", s)
	}
	return fmt.Sprintf("%d min %d s", m, s)
}

// AdminSchemaUpdateStatus: GET /admin/api/schema-update -- the view, or
// {"state":"none"}.  Any signed-in role: the notice is for everyone who
// opens the admin UI, the buttons are not.
func (h *Handler) AdminSchemaUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.SchemaRefresh(ctx)
	role := ""
	if pay := SessionFromContext(r); pay != nil {
		role = pay.Role
	}
	v := h.schemaView(role, i18n.Resolve(r))
	if v == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "none", "now": time.Now().Unix()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// AdminSchemaUpdateRun: POST /admin/api/schema-update/run (superadmin).
func (h *Handler) AdminSchemaUpdateRun(w http.ResponseWriter, r *http.Request) {
	pay := SessionFromContext(r)
	by := "admin"
	if pay != nil && h.UserRepo != nil {
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil && u != nil {
			by = u.Username
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.SchemaRefresh(ctx)
	if waiting, running := h.SchemaWaiting(); waiting == 0 || running {
		err := errSchemaNothing
		if running {
			err = db.ErrSchemaUpdateRunning
		}
		writeJSON(w, http.StatusConflict, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	// The audit row first: it is a write, and from the moment the run is
	// started the write lock may be its own.
	if h.UserRepo != nil && pay != nil {
		h.UserRepo.Record(r.Context(), pay.UserID, by, "schema_update.run", "", "")
	}
	if err := h.schemaStart(by); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errSchemaNothing) || errors.Is(err, db.ErrSchemaUpdateRunning) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// AdminSchemaUpdateCancel: POST /admin/api/schema-update/cancel (superadmin).
func (h *Handler) AdminSchemaUpdateCancel(w http.ResponseWriter, r *http.Request) {
	if err := h.schemaCancel(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

var (
	errSchemaNothing = errors.New("no schema update is waiting")
	errSchemaNotOurs = errors.New("the running schema update was not started by this daemon; stop it where it was started")
)

// schemaStart starts the update as a child process.
func (h *Handler) schemaStart(by string) error {
	u := &h.schema
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.going() {
		return db.ErrSchemaUpdateRunning
	}
	if len(u.waiting) == 0 {
		return errSchemaNothing
	}
	cmd, err := h.schemaCommand(by)
	if err != nil {
		return err
	}
	// From here the run may take the write lock at any moment: hold the
	// daemon's writers before it does, not when the record is first seen.
	if h.DB.SchemaUpdateHoldsWrites() {
		h.DB.HoldWrites(true)
	}
	if err := cmd.Start(); err != nil {
		h.DB.HoldWrites(false)
		return fmt.Errorf("start the schema update: %w", err)
	}
	u.child, u.childStarted = cmd, time.Now()
	log.Printf("schema update: started by %s (pid %d)", LogSafe(by), cmd.Process.Pid)
	go func() {
		defer safe.Recover("schema-update-wait")
		err := cmd.Wait()
		u.mu.Lock()
		u.child, u.childStarted = nil, time.Time{}
		u.mu.Unlock()
		if err != nil {
			log.Printf("schema update: ended with %v", err)
		} else {
			log.Printf("schema update: finished")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.SchemaRefresh(ctx)
	}()
	return nil
}

// schemaCancel stops the run this daemon started.
func (h *Handler) schemaCancel() error {
	u := &h.schema
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.child == nil || u.child.Process == nil {
		if u.running {
			return errSchemaNotOurs
		}
		return errSchemaNothing
	}
	log.Printf("schema update: cancel requested (pid %d)", u.child.Process.Pid)
	return u.child.Process.Signal(syscall.SIGTERM)
}

// schemaCommand builds the child: this binary, `migrate`.
func (h *Handler) schemaCommand(by string) (*exec.Cmd, error) {
	if h.SchemaCommand != nil {
		return h.SchemaCommand(by)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find this binary: %w", err)
	}
	args := []string{"migrate", "-by", by}
	if h.ConfigPath != "" {
		args = append(args, "-config", h.ConfigPath)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = os.Environ()
	out := &logLines{prefix: "schema update: "}
	cmd.Stdout, cmd.Stderr = out, out
	return cmd, nil
}

// logLines writes what it is given to the log, a line at a time.
type logLines struct {
	prefix string
	mu     sync.Mutex
	buf    []byte
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := strings.IndexByte(string(l.buf), '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(l.buf[:i])); line != "" {
			log.Print(l.prefix + line)
		}
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

// schemaWriteExempt: the requests that go through while the database's
// writes are held -- the ones that do not write to it, and the one that ends
// the hold.
func (h *Handler) schemaWriteExempt(r *http.Request) bool {
	p := strings.TrimPrefix(r.URL.Path, h.cfg().Server.BasePath)
	return strings.HasPrefix(p, "/admin/api/schema-update") || p == "/admin/logout"
}

// respondWritesHeld answers a change that cannot be made now, because a schema
// update holds the database's write lock.  Waiting out the lock would be a
// request that hangs and then fails with a driver error; this says what is
// going on and when to come back.
func (h *Handler) respondWritesHeld(w http.ResponseWriter, r *http.Request) {
	lang := i18n.Resolve(r)
	msg := i18n.T(lang, "schema_update.writes_held")
	w.Header().Set("Retry-After", "60")
	if strings.HasPrefix(r.URL.Path, h.cfg().Server.BasePath+"/admin/api/") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": 0, "error": "schema_update_running", "message": msg})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	// Back to the page the change was made from, when that is one of ours.
	back := h.cfg().Server.BasePath + "/admin/"
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host && strings.HasPrefix(ref.Path, h.cfg().Server.BasePath+"/admin/") {
		back = ref.RequestURI()
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><title>unmask</title></head>`+
		`<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;padding:3rem 1.5rem">`+
		`<div style="max-width:36rem;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:.4rem;padding:1.25rem 1.5rem;line-height:1.6">`+
		`<p style="margin:0 0 1rem">%s</p><p style="margin:0"><a href="%s">%s</a></p></div></body></html>`,
		html.EscapeString(string(lang)), html.EscapeString(msg), html.EscapeString(back), html.EscapeString(i18n.T(lang, "schema_update.back")))
}
