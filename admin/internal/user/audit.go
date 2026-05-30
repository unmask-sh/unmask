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
	At       string // ISO8601-ish.  Driver-dependent (= easy to scan as string).
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
	// Omit At from the insert so the DB's CURRENT_TIMESTAMP default fires --
	// but we still set it above for safety; either way is fine.
	if err := r.DB.Gorm.WithContext(ctx).Create(&row).Error; err != nil {
		log.Printf("audit insert failed: %v", err)
	}
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
	q := `SELECT id, user_id, username, action, target, detail, at
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
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Detail, &atRaw); err != nil {
			return nil, err
		}
		e.At = formatAt(atRaw)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// GetAuditByID fetches a single audit row.  Returns (nil, nil) if not found.
// Used by the audit restore handler to retrieve the `before` snapshot.
func (r *Repository) GetAuditByID(ctx context.Context, id int64) (*AuditEntry, error) {
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, user_id, username, action, target, detail, at
		 FROM unmask_user_audit WHERE id = ?`, id)
	var e AuditEntry
	var atRaw any
	if err := row.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Detail, &atRaw); err != nil {
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
