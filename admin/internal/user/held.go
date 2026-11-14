package user

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/spill"
)

// Writes kept while a schema update holds the database's write lock.
//
// An audit row and a last-login time are written on the request that causes
// them -- a sign-in, a settings save.  On SQLite, while a schema update builds
// an index, such a write waits out the busy timeout and then fails: a sign-in
// took ten seconds and lost its audit row, and every change in the admin UI
// had to be refused for as long as the build ran, the settings that answer an
// attack among them.  They are kept here instead, with the time they happened,
// and written once the lock is free (FlushHeld).

// heldAuditMax bounds the audit rows kept while writes are held: a sign-in or
// a save each, over the minutes a build takes.
const heldAuditMax = 5000

type heldWrites struct {
	mu      sync.Mutex
	audits  []db.UserAudit
	logins  map[int64]time.Time
	dropped int
}

// holdAudit keeps row for later when writes are held, and reports whether it
// did.
func (r *Repository) holdAudit(row db.UserAudit) bool {
	if r.DB == nil || !r.DB.WritesHeld() {
		return false
	}
	r.keepAudit(row)
	return true
}

// keepAudit keeps row for later, whatever the flag says now: for a write the
// database refused as held (ErrWritesHeld) in the moment between the check
// and the write.
func (r *Repository) keepAudit(row db.UserAudit) {
	r.held.mu.Lock()
	defer r.held.mu.Unlock()
	if len(r.held.audits) >= heldAuditMax {
		if r.held.dropped == 0 {
			log.Printf("audit: %d rows are waiting for the schema update to finish; further ones are not kept", heldAuditMax)
		}
		r.held.dropped++
		return
	}
	r.held.audits = append(r.held.audits, row)
}

// holdLogin keeps a sign-in's time for later when writes are held, and
// reports whether it did.
func (r *Repository) holdLogin(userID int64, at time.Time) bool {
	if r.DB == nil || !r.DB.WritesHeld() {
		return false
	}
	r.keepLogin(userID, at)
	return true
}

// keepLogin is holdLogin whatever the flag says now (see keepAudit).
func (r *Repository) keepLogin(userID int64, at time.Time) {
	r.held.mu.Lock()
	defer r.held.mu.Unlock()
	if r.held.logins == nil {
		r.held.logins = map[int64]time.Time{}
	}
	r.held.logins[userID] = at
}

// FlushHeld writes the audit rows and sign-in times kept while writes were
// held.  Called when the hold ends and when the daemon stops.  A row that
// cannot be written now is dropped with a line in the log: the audit log is
// best-effort everywhere else too (Record).
func (r *Repository) FlushHeld(ctx context.Context) {
	if r == nil || r.DB == nil {
		return
	}
	r.held.mu.Lock()
	audits, logins, dropped := r.held.audits, r.held.logins, r.held.dropped
	r.held.audits, r.held.logins, r.held.dropped = nil, nil, 0
	r.held.mu.Unlock()
	if len(audits) == 0 && len(logins) == 0 {
		return
	}
	wroteAudits, wroteLogins, keptAgain := 0, 0, 0
	var lastErr error
	// locked: a write failed for the lock alone (a run from the shell holds
	// it, and this daemon has not seen that yet: a start, a stop).  What is
	// left is kept again without a try -- each would wait out the busy
	// timeout -- for the next flush, or the stop's spill file.
	locked := false
	for i := range audits {
		if !locked {
			err := r.DB.Gorm.WithContext(ctx).Create(&audits[i]).Error
			if err == nil {
				wroteAudits++
				continue
			}
			lastErr = err
			if !db.IsTransientWriteErr(err) {
				continue
			}
			locked = true
		}
		audits[i].ID = 0
		r.keepAudit(audits[i])
		keptAgain++
	}
	for id, at := range logins {
		if !locked {
			err := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("last_login", at).Error
			if err == nil {
				wroteLogins++
				continue
			}
			lastErr = err
			if !db.IsTransientWriteErr(err) {
				continue
			}
			locked = true
		}
		r.keepLogin(id, at)
		keptAgain++
	}
	if keptAgain > 0 {
		log.Printf("audit: the database is still locked; %d row(s) and sign-in time(s) kept for the next try", keptAgain)
	}
	log.Printf("audit: wrote %d of %d row(s) and %d of %d sign-in time(s) kept during the schema update (%d more rows were not kept)",
		wroteAudits, len(audits), wroteLogins, len(logins), dropped)
	if lastErr != nil {
		log.Printf("audit: writing what was kept: %v", lastErr)
	}
}

// HeldSpillFile is the file the audit rows and sign-in times kept through a
// hold are carried in across a stop of the daemon (package spill).
const HeldSpillFile = "held-audit.json"

type spilledWrites struct {
	Audits []db.UserAudit
	Logins map[int64]time.Time
}

// SpillHeld writes the audit rows and sign-in times still kept -- the
// database's writes were held to the end, by a run from the shell -- to dir
// for the next start, and reports how many.  For the shutdown.
func (r *Repository) SpillHeld(dir string) (int, error) {
	if r == nil {
		return 0, nil
	}
	r.held.mu.Lock()
	s := spilledWrites{Audits: append([]db.UserAudit(nil), r.held.audits...), Logins: map[int64]time.Time{}}
	for id, at := range r.held.logins {
		s.Logins[id] = at
	}
	r.held.mu.Unlock()
	n := len(s.Audits) + len(s.Logins)
	if n == 0 {
		return 0, nil
	}
	return n, spill.Save(dir, HeldSpillFile, s)
}

// RestoreSpilled takes back what a stop during a hold carried over, kept
// again within the same bound, and reports how many; FlushHeld writes it once
// writes are free.  For the start.
func (r *Repository) RestoreSpilled(dir string) (int, error) {
	if r == nil {
		return 0, nil
	}
	var s spilledWrites
	found, err := spill.Take(dir, HeldSpillFile, &s)
	if !found || err != nil {
		return 0, err
	}
	for _, a := range s.Audits {
		a.ID = 0 // the table numbers it when it is written
		r.keepAudit(a)
	}
	for id, at := range s.Logins {
		r.keepLogin(id, at)
	}
	return len(s.Audits) + len(s.Logins), nil
}
