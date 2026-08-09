// audit log: append "who / when / what / how" entries to unmask_user_audit.
//
// What to log:
//   - login / logout / login_failed
//   - settings save (= per section)
//   - ban clear
//   - user create / delete / set_role / reset_password
//   - call Record() before/after each mutation handler
//
// detail is a JSON string.  The schema may differ per action (= free payload).
package user

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// AuditEntry: one record (= for the viewer UI).
type AuditEntry struct {
	ID       int64
	UserID   sql.NullInt64
	Username string
	Action   string
	Target   sql.NullString
	Detail   sql.NullString
	IP       sql.NullString // client IP; empty for pre-0024 rows and CLI callers
	At       string         // ISO8601-ish.  Driver-dependent (= easy to scan as string).
}

// Record: append one audit entry.  Best-effort: the caller continues even on failure.
//
// userID == 0 is anonymous (= login failure / bootstrap etc.).
func (r *Repository) Record(ctx context.Context, userID int64, username, action, target, detailJSON string) {
	row := db.UserAudit{Username: username, Action: action, At: time.Now()}
	if userID > 0 {
		row.UserID = &userID
	}
	if target != "" {
		row.Target = &target
	}
	if detailJSON != "" {
		row.Detail = &detailJSON
	}
	// Filled by the admin middleware, which already resolves the real client
	// address behind any proxy.  Absent for CLI / cron callers.
	if ip := ClientIPFromContext(ctx); ip != "" {
		row.IP = &ip
	}
	// Omit At from the insert so the DB's CURRENT_TIMESTAMP default fires --
	// but we still set it above for safety; either way is fine.
	if err := r.DB.Gorm.WithContext(ctx).Create(&row).Error; err != nil {
		// A canceled request context (the admin client disconnected before the
		// audit row landed, or the daemon is stopping) is expected, not a fault
		// -- match the unmask_event insert and only log a live-context failure.
		if ctx.Err() == nil {
			log.Printf("audit insert failed: %v", err)
		}
	}
}

// PruneOldAudit deletes audit rows older than retentionDays.  retentionDays <= 0
// disables pruning (= keep forever).  Mirrors events.PruneOldEvents: the cutoff
// is computed in Go and bound as a time.Time so the "<" comparison stays portable
// across the mysql + glebarez/modernc drivers (no datetime() vs DATE_SUB branch).
// Without this the admin-action log grew unbounded.
func (r *Repository) PruneOldAudit(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 || r.DB == nil {
		return 0, nil
	}
	// .UTC(): `at` is stored UTC-at-rest; a host-local cutoff would skew the
	// retention boundary by the host TZ offset under the sqlite driver.
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	res, err := r.DB.ExecContext(ctx, `DELETE FROM unmask_user_audit WHERE at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListAudit: paging for the viewer UI.  Newest first.  limit / offset paging.
// If userIDFilter > 0, restrict to that user.
func (r *Repository) ListAudit(ctx context.Context, limit, offset int, userIDFilter int64) ([]*AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT id, user_id, username, action, target, detail, ip, at
	      FROM unmask_user_audit`
	args := []any{}
	if userIDFilter > 0 {
		q += ` WHERE user_id = ?`
		args = append(args, userIDFilter)
	}
	q += ` ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := r.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var atRaw any
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Detail, &e.IP, &atRaw); err != nil {
			return nil, err
		}
		e.At = formatAt(atRaw)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// CountAudit: row count for the same filter ListAudit uses, so callers can
// build a numbered pager (= "1-50 of 697").  Cheap on unmask_user_audit
// because the table stays compact (~10^3 rows in practice); large append-
// only logs (= unmask_event) should use seek pagination instead.
func (r *Repository) CountAudit(ctx context.Context, userIDFilter int64) (int, error) {
	q := `SELECT COUNT(*) FROM unmask_user_audit`
	args := []any{}
	if userIDFilter > 0 {
		q += ` WHERE user_id = ?`
		args = append(args, userIDFilter)
	}
	var n int
	if err := r.DB.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetAuditByID fetches a single audit row.  Returns (nil, nil) if not found.
// Used by the audit restore handler to retrieve the `before` snapshot.
func (r *Repository) GetAuditByID(ctx context.Context, id int64) (*AuditEntry, error) {
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, user_id, username, action, target, detail, ip, at
		 FROM unmask_user_audit WHERE id = ?`, id)
	var e AuditEntry
	var atRaw any
	if err := row.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Detail, &e.IP, &atRaw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	e.At = formatAt(atRaw)
	return &e, nil
}

// formatAt: drivers return the timestamp as time.Time / string / []byte; absorb.
// modernc.org/sqlite (= pure-Go) returns DATETIME columns as time.Time, so we
// stringify with a stable ISO-ish layout that matches what the MariaDB driver
// would hand back as a string (= "2026-05-19 10:53:09").
func formatAt(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case time.Time:
		return x.Format("2006-01-02 15:04:05")
	default:
		return ""
	}
}
