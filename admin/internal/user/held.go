package user

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
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
	r.held.mu.Lock()
	defer r.held.mu.Unlock()
	if len(r.held.audits) >= heldAuditMax {
		if r.held.dropped == 0 {
			log.Printf("audit: %d rows are waiting for the schema update to finish; further ones are not kept", heldAuditMax)
		}
		r.held.dropped++
		return true
	}
	r.held.audits = append(r.held.audits, row)
	return true
}

// holdLogin keeps a sign-in's time for later when writes are held, and
// reports whether it did.
func (r *Repository) holdLogin(userID int64, at time.Time) bool {
	if r.DB == nil || !r.DB.WritesHeld() {
		return false
	}
	r.held.mu.Lock()
	defer r.held.mu.Unlock()
	if r.held.logins == nil {
		r.held.logins = map[int64]time.Time{}
	}
	r.held.logins[userID] = at
	return true
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
	wroteAudits, wroteLogins := 0, 0
	var lastErr error
	for i := range audits {
		if err := r.DB.Gorm.WithContext(ctx).Create(&audits[i]).Error; err != nil {
			lastErr = err
			continue
		}
		wroteAudits++
	}
	for id, at := range logins {
		if err := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("last_login", at).Error; err != nil {
			lastErr = err
			continue
		}
		wroteLogins++
	}
	log.Printf("audit: wrote %d of %d row(s) and %d of %d sign-in time(s) kept during the schema update (%d more rows were not kept)",
		wroteAudits, len(audits), wroteLogins, len(logins), dropped)
	if lastErr != nil {
		log.Printf("audit: writing what was kept: %v", lastErr)
	}
}
