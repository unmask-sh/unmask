package handlers

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The credential endpoints' counters in the database.
//
// loginThrottle counted in this process's memory: a restart forgot every
// lock, and behind a load balancer each node kept its own count, so N
// nodes allowed an address N times the failures before any of them locked
// it.  The counters now live in unmask_login_throttle (migration 0050),
// one row per key, so a lock survives the daemon and every node on a
// shared database reads and advances the same count.  The memory cells
// remain the fallback for the moments the table cannot be used: no
// database yet, its writes held by a schema update, an error -- counted
// on this node alone until the next call reaches the table.
//
// On SQLite one failed login is one short write transaction (an upsert,
// an update, a read), a few hundred microseconds next to the argon2 check
// that precedes it; a lookup is one indexed read.  The rows are pruned
// hourly with the aggregates (dashboard.PruneHourly).

// throttleDBTimeout bounds one counter operation: a database that does
// not answer in this time is treated as absent for the call.
const throttleDBTimeout = 3 * time.Second

// loginThrottleStore is the database side of loginThrottle.
type loginThrottleStore struct {
	db   *db.DB
	warn sync.Once
}

// usable reports whether the table may be used right now.
func (s *loginThrottleStore) usable() bool {
	return s != nil && s.db != nil && s.db.Gorm != nil && !s.db.WritesHeld()
}

// fallback logs the first error that sent a call to the memory cells.
func (s *loginThrottleStore) fallback(op string, err error) {
	s.warn.Do(func() {
		log.Printf("login throttle: %s on the database failed (%v); counting in this node's memory until it answers", op, err)
	})
}

func (s *loginThrottleStore) lockedFor(key string, now time.Time) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), throttleDBTimeout)
	defer cancel()
	var row db.LoginThrottle
	err := s.db.Gorm.WithContext(ctx).Where("k = ?", key).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return remainingLock(row.LockedUntil, now), nil
}

// note counts one event against key in one transaction: the row is made
// if it is not there; the count moves on -- from one when the window has
// run out -- unless the key is locked; and a count at the limit trips the
// lock.  Two nodes counting the same key at once each add their event: the
// update is one statement on the row.
func (s *loginThrottleStore) note(key string, now time.Time, limit int, window, lock time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), throttleDBTimeout)
	defer cancel()
	n, w := now.Unix(), int64(window/time.Second)
	var remaining time.Duration
	err := s.db.Gorm.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&db.LoginThrottle{K: key, WindowStart: n, UpdatedAt: n}).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE unmask_login_throttle
			SET cnt = CASE WHEN window_start + ? <= ? THEN 1 ELSE cnt + 1 END,
			    window_start = CASE WHEN window_start + ? <= ? THEN ? ELSE window_start END,
			    updated_at = ?
			WHERE k = ? AND locked_until <= ?`, w, n, w, n, n, n, key, n).Error; err != nil {
			return err
		}
		var row db.LoginThrottle
		if err := tx.Where("k = ?", key).Take(&row).Error; err != nil {
			return err
		}
		if r := remainingLock(row.LockedUntil, now); r > 0 {
			remaining = r
			return nil
		}
		if row.Cnt >= limit {
			if err := tx.Exec(`UPDATE unmask_login_throttle SET locked_until = ?, cnt = 0, updated_at = ? WHERE k = ?`,
				n+int64(lock/time.Second), n, key).Error; err != nil {
				return err
			}
			remaining = lock
		}
		return nil
	})
	return remaining, err
}

// forgive takes own's count, as far as it is inside the window, off key's,
// and drops own's row: one transaction.  A key that is locked keeps its
// lock.
func (s *loginThrottleStore) forgive(key, own string, now time.Time, window time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), throttleDBTimeout)
	defer cancel()
	n, w := now.Unix(), int64(window/time.Second)
	return s.db.Gorm.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row db.LoginThrottle
		err := tx.Where("k = ?", own).Take(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if row.Cnt > 0 && row.WindowStart+w > n {
			if err := tx.Exec(`UPDATE unmask_login_throttle
				SET cnt = CASE WHEN cnt > ? THEN cnt - ? ELSE 0 END, updated_at = ?
				WHERE k = ? AND locked_until <= ?`, row.Cnt, row.Cnt, n, key, n).Error; err != nil {
				return err
			}
		}
		return tx.Where("k = ?", own).Delete(&db.LoginThrottle{}).Error
	})
}

// remainingLock is how much longer a lock that holds until the unix time
// until lasts at now (0 = none).
func remainingLock(until int64, now time.Time) time.Duration {
	if d := until - now.Unix(); d > 0 {
		return time.Duration(d) * time.Second
	}
	return 0
}

// lockedFor returns how much longer the key is locked (0 = not locked).
func (t *loginThrottle) lockedFor(key string, now time.Time) time.Duration {
	if t.store.usable() {
		d, err := t.store.lockedFor(throttleDBKey(key), now)
		if err == nil {
			return d
		}
		t.store.fallback("lookup", err)
	}
	return t.lockedForMem(key, now)
}

// note records one event (a login failure, or a forgot-password request)
// against key and returns the remaining lock if this event tripped or renewed
// it.  limit/window/lock describe the axis being counted.
func (t *loginThrottle) note(key string, now time.Time, limit int, window, lock time.Duration) time.Duration {
	if t.store.usable() {
		d, err := t.store.note(throttleDBKey(key), now, limit, window, lock)
		if err == nil {
			return d
		}
		t.store.fallback("count", err)
	}
	return t.noteMem(key, now, limit, window, lock)
}

// forgive is what a successful login does to the address's count: the
// failures counted for the account that has just signed in (own) come off
// it, and own's count is dropped.  On both sides: a count the memory took
// while the database was away must not lock the address that has since
// signed in.
//
// It used to be the whole count that went -- "a successful login is a clean
// slate" -- whoever the failures had been for.  The holder of any account,
// a viewer's included, could then guess at another account's password
// without end from one address: nine guesses, a login of their own, nine
// more.  The owner of an account still loses nothing by mistyping their own
// password before getting it right; guesses at someone else's stay counted.
func (t *loginThrottle) forgive(key, own string, now time.Time) {
	if t.store.usable() {
		if err := t.store.forgive(throttleDBKey(key), throttleDBKey(own), now, t.failWindow); err != nil {
			t.store.fallback("forgive", err)
		}
	}
	t.forgiveMem(key, own, now)
}

// noteOwn counts a failure for the account it was aimed at (own), beside
// the address's count: what forgive takes off when that account signs in.
// It never locks anything by itself.
func (t *loginThrottle) noteOwn(own string, now time.Time) {
	t.note(own, now, ownFailuresNeverLock, t.failWindow, t.lockFor)
}

// ownFailuresNeverLock: the limit of an account's own count.  The lock is
// the address's; this count only remembers whose the failures were.
const ownFailuresNeverLock = 1 << 30

// throttleDBKey is the key as the column holds it: a key longer than the
// column (an address that did not parse, kept as it came) is cut, so the
// row is written rather than refused.
func throttleDBKey(key string) string {
	if len(key) > 80 {
		return key[:80]
	}
	return key
}
