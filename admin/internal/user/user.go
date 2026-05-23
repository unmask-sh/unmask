// Package user: internal user management (= local DB).
//
// Three-tier role hierarchy (= zabbix-style):
//   - superadmin : user management + every feature
//   - admin      : every setting + ban operations.  cannot manage users
//   - viewer     : read-only
//
// Passwords are hashed with bcrypt.  cost 12 (= within the recommended
// range as of 2026).
//
// Authentication flow:
//  1. Login form receives username + password.
//  2. Verify(username, password) runs bcrypt verification.
//  3. On success, issue a session cookie (= cookies pkg) with user_id +
//     role in the payload.
package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

const (
	RoleSuperadmin = "superadmin"
	RoleAdmin      = "admin"
	RoleViewer     = "viewer"
)

// IsValidRole: validate a role string coming from yml / form / cli.
func IsValidRole(r string) bool {
	return r == RoleSuperadmin || r == RoleAdmin || r == RoleViewer
}

// CanManageUsers: superadmin only.
func CanManageUsers(role string) bool { return role == RoleSuperadmin }

// CanWrite: whether the role can mutate (= save settings / clear bans / etc.).
// superadmin / admin only.  viewer can only GET.
func CanWrite(role string) bool { return role == RoleSuperadmin || role == RoleAdmin }

// CanReadAudit: whether the role can view other people's audit log.
// admin and above.  viewer cannot.  editor is gone (= merged into admin).
func CanReadAudit(role string) bool { return role == RoleSuperadmin || role == RoleAdmin }

// User: one row of unmask_user.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	// Email: optional.  Destination for notifications / password reset.
	Email sql.NullString
	// AlertOptOut: 1 means don't deliver alert mail.  default 0.
	AlertOptOut bool
	// ResetToken / ResetTokenExpiresAt: for the password reset link.  Expires is unix-sec.
	ResetToken          sql.NullString
	ResetTokenExpiresAt sql.NullInt64
	CreatedAt           time.Time
	LastLogin           sql.NullTime
}

// ErrNotFound: user not found.  Also used for "auth failed" so that the
// caller can treat "username doesn't exist" vs "wrong password"
// identically to avoid a timing leak.
var ErrNotFound = errors.New("user not found")

// ErrUsernameTaken: clash with an existing username.
var ErrUsernameTaken = errors.New("username already taken")

// ErrLastSuperadmin: returned when trying to delete / demote a
// superadmin while they are the only one.  Prevents "delete yourself
// and end up with zero users."
var ErrLastSuperadmin = errors.New("cannot remove the last superadmin")

// HashPassword: hash with bcrypt at cost 12.  Reject empty / over-long
// passwords (= > 72 bytes) (= bcrypt only sees the first 72 bytes, so
// reject to avoid silent truncation).
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("password is empty")
	}
	if len(plain) > 72 {
		return "", errors.New("password too long (max 72 bytes)")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), 12)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword: bcrypt verify.  Returns nil on match.
func CheckPassword(hash, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

// Repository: thin CRUD wrapper for the unmask_user table.
type Repository struct{ DB *db.DB }

func New(d *db.DB) *Repository { return &Repository{DB: d} }

// Count: number of registered users.  Used by bootstrap to decide
// "if there are no users, seed one."
func (r *Repository) Count(ctx context.Context) (int, error) {
	var n int
	err := r.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_user`).Scan(&n)
	return n, err
}

// Create: a new user.  Pass plaintext for password.  Hashing happens here.
// Clash with an existing username -> ErrUsernameTaken.
func (r *Repository) Create(ctx context.Context, username, plainPassword, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is empty")
	}
	if !IsValidRole(role) {
		return nil, fmt.Errorf("invalid role: %q", role)
	}
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return nil, err
	}
	_, err = r.DB.ExecContext(ctx,
		`INSERT INTO unmask_user (username, password_hash, role) VALUES (?, ?, ?)`,
		username, hash, role)
	if err != nil {
		// Both SQLite and MySQL produce driver-specific UNIQUE violation
		// messages, so do a coarse check (= contains "UNIQUE constraint"
		// / "Duplicate entry").
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE constraint") || strings.Contains(msg, "Duplicate entry") {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	return r.GetByUsername(ctx, username)
}

// GetByUsername: primary lookup used during authentication.
func (r *Repository) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE username = ?`, username)
	return scanUser(row)
}

// GetByID: load the user from the session cookie payload (= user_id).
func (r *Repository) GetByID(ctx context.Context, id int64) (*User, error) {
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE id = ?`, id)
	return scanUser(row)
}

// List: for the superadmin user-management UI.  Ascending by username.
func (r *Repository) List(ctx context.Context) ([]*User, error) {
	rows, err := r.DB.QueryContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword: password reset.  Shared by CLI / admin UI.
func (r *Repository) SetPassword(ctx context.Context, userID int64, plainPassword string) error {
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return err
	}
	res, err := r.DB.ExecContext(ctx,
		`UPDATE unmask_user SET password_hash = ? WHERE id = ?`, hash, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRole: superadmin changes a role.  Prevent "demote the last superadmin."
func (r *Repository) SetRole(ctx context.Context, userID int64, newRole string) error {
	if !IsValidRole(newRole) {
		return fmt.Errorf("invalid role: %q", newRole)
	}
	cur, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if cur.Role == RoleSuperadmin && newRole != RoleSuperadmin {
		// About to demote.  Check whether there's another superadmin.
		var n int
		if err := r.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM unmask_user WHERE role = ?`, RoleSuperadmin).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastSuperadmin
		}
	}
	_, err = r.DB.ExecContext(ctx, `UPDATE unmask_user SET role = ? WHERE id = ?`, newRole, userID)
	return err
}

// Delete: remove the user.  The last superadmin cannot be removed.
func (r *Repository) Delete(ctx context.Context, userID int64) error {
	cur, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if cur.Role == RoleSuperadmin {
		var n int
		if err := r.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM unmask_user WHERE role = ?`, RoleSuperadmin).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastSuperadmin
		}
	}
	_, err = r.DB.ExecContext(ctx, `DELETE FROM unmask_user WHERE id = ?`, userID)
	return err
}

// TouchLastLogin: update last_login on successful authentication.
// best-effort (= login itself succeeds even if this fails).
func (r *Repository) TouchLastLogin(ctx context.Context, userID int64) {
	_, _ = r.DB.ExecContext(ctx,
		`UPDATE unmask_user SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, userID)
}

// scanUser: scanner that handles both QueryRow / Rows.  Includes
// email/alert_opt_out/reset_*.
func scanUser(r interface {
	Scan(...any) error
}) (*User, error) {
	var u User
	var optOut int64
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Email, &optOut, &u.ResetToken, &u.ResetTokenExpiresAt, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.AlertOptOut = optOut != 0
	return &u, nil
}

// SetProfile: superadmin updates a user's email + alert_opt_out.  Also
// invoked when a user updates their own profile page.
func (r *Repository) SetProfile(ctx context.Context, userID int64, email string, alertOptOut bool) error {
	email = strings.TrimSpace(email)
	var emailVal any
	if email == "" {
		emailVal = nil
	} else {
		emailVal = email
	}
	optOut := 0
	if alertOptOut {
		optOut = 1
	}
	res, err := r.DB.ExecContext(ctx,
		`UPDATE unmask_user SET email = ?, alert_opt_out = ? WHERE id = ?`,
		emailVal, optOut, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateWithProfile: create a new user including email + alert_opt_out.
func (r *Repository) CreateWithProfile(ctx context.Context, username, plainPassword, role, email string, alertOptOut bool) (*User, error) {
	u, err := r.Create(ctx, username, plainPassword, role)
	if err != nil {
		return nil, err
	}
	if email != "" || alertOptOut {
		if err := r.SetProfile(ctx, u.ID, email, alertOptOut); err != nil {
			return nil, err
		}
		u, err = r.GetByID(ctx, u.ID)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}

// IssueResetToken: generate a token (= 32-byte hex) and persist it.
// Expires after ttlSec.  Returns the generated token.  Overwrites any
// existing token (= the previous reset's token becomes invalid).
func (r *Repository) IssueResetToken(ctx context.Context, userID int64, token string, ttlSec int64) error {
	expires := time.Now().Unix() + ttlSec
	res, err := r.DB.ExecContext(ctx,
		`UPDATE unmask_user SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?`,
		token, expires, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ConsumeResetToken: if the token is valid, return the user and consume
// the token (= NULL out the column).  Expired / mismatched token / user
// not found all return ErrNotFound.
func (r *Repository) ConsumeResetToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE reset_token = ?`, token)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	if !u.ResetTokenExpiresAt.Valid || u.ResetTokenExpiresAt.Int64 < time.Now().Unix() {
		// Expired.  Wipe the token and fail.
		_, _ = r.DB.ExecContext(ctx,
			`UPDATE unmask_user SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?`, u.ID)
		return nil, ErrNotFound
	}
	// Consume (= one-shot).
	if _, err := r.DB.ExecContext(ctx,
		`UPDATE unmask_user SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?`, u.ID); err != nil {
		return nil, err
	}
	return u, nil
}

// GetByEmail: for forgot-password, look up by email instead of username.
// When multiple users share the same email (= possible at the data level),
// return the first one.  ErrNotFound when missing.
func (r *Repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, ErrNotFound
	}
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE email = ? ORDER BY id LIMIT 1`, email)
	return scanUser(row)
}

// AlertRecipients: load the users that should receive alert mail
// (= email present + alert_opt_out=0 + role in superadmin/admin).
// Called from the notifier.  viewers do not receive notifications.
func (r *Repository) AlertRecipients(ctx context.Context) ([]string, error) {
	rows, err := r.DB.QueryContext(ctx,
		`SELECT email FROM unmask_user
		 WHERE email IS NOT NULL AND email <> '' AND alert_opt_out = 0 AND role IN (?, ?)`,
		RoleSuperadmin, RoleAdmin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e sql.NullString
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		if e.Valid && strings.TrimSpace(e.String) != "" {
			out = append(out, e.String)
		}
	}
	return out, rows.Err()
}
