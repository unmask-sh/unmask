// Package user: internal user management (= local DB).
//
// Three-tier role hierarchy (= zabbix-style):
//   - superadmin : user management + every feature
//   - admin      : every setting + ban operations.  cannot manage users
//   - viewer     : read-only
//
// Passwords are hashed with argon2id (= memory-hard, PHC string format).
// OWASP 2024 baseline parameters: m=64MiB, t=2, p=1.
//
// Authentication flow:
//  1. Login form receives username + password.
//  2. CheckPassword(stored, plain) runs argon2id verification.
//  3. On success, issue a session cookie (= cookies pkg) with user_id +
//     role in the payload.
package user

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

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
	// Disabled: 1 suspends the account — sign-in refused, sessions cut on the
	// next request, alert mail skipped — while the row (role, email, history)
	// is kept for re-enabling.  The deletion-free way to lock someone out.
	Disabled bool
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

// argon2id parameters (= OWASP 2024 baseline).  Memory is the dominant cost
// factor for an attacker with a GPU farm, so push memory before iterations.
const (
	argon2Memory  uint32 = 64 * 1024 // 64 MiB
	argon2Time    uint32 = 2
	argon2Threads uint8  = 1
	argon2KeyLen  uint32 = 32
	argon2SaltLen        = 16
	// MaxPasswordLen: argon2 itself has no length limit, but a multi-MB
	// password input would force the host to hash megabytes per login attempt.
	// 1 KiB is well over any realistic passphrase.
	MaxPasswordLen = 1024
)

// MinPasswordLen is the minimum length for a new admin password.  Shared by the
// setup wizard and the `user` CLI so the CLI (which can create the first
// superadmin) cannot mint a weaker account than the wizard allows.
const MinPasswordLen = 8

// ValidatePassword enforces the length policy for a NEW password (not the verify
// path -- an existing short password must still authenticate).
func ValidatePassword(plain string) error {
	if len(plain) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(plain) > MaxPasswordLen {
		return fmt.Errorf("password too long (max %d bytes)", MaxPasswordLen)
	}
	return nil
}

// HashPassword: hash with argon2id and return a PHC string
// (= `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`).  Reject empty /
// pathologically long inputs.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("password is empty")
	}
	if len(plain) > MaxPasswordLen {
		return "", fmt.Errorf("password too long (max %d bytes)", MaxPasswordLen)
	}
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		enc(salt), enc(key)), nil
}

// CheckPassword: verify against an argon2id PHC string.  Returns nil on match.
func CheckPassword(hash, plain string) error {
	return checkArgon2id(hash, plain)
}

// NeedsRehash reports whether a stored argon2id PHC hash was produced with cost
// parameters that differ from the current HashPassword defaults, so a
// successful login can transparently re-hash at the stronger cost (AUTH-6).  An
// unparseable or non-argon2id string also returns true, upgrading a legacy
// format on next login.
func NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return true
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return true
	}
	return m != argon2Memory || t != argon2Time || p != argon2Threads
}

// errBadHash: parse failure or argon2id mismatch.  Returned as a single value
// to avoid leaking which step failed (= argon2 verify is constant-time, so
// don't unmask the failure mode either).
var errBadHash = errors.New("password mismatch")

func checkArgon2id(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	// PHC format: "" / argon2id / v=N / m=...,t=...,p=... / salt / hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errBadHash
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return errBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errBadHash
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errBadHash
	}
	keyLen := uint32(len(expected))
	if keyLen == 0 {
		return errBadHash
	}
	actual := argon2.IDKey([]byte(plain), salt, time, memory, threads, keyLen)
	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return errBadHash
	}
	return nil
}

// dummyHash is a real argon2id hash (same params as HashPassword) computed once
// at startup.  DummyCheckPassword verifies against it so a login for a
// non-existent username spends the same CPU as a real one -- no username
// enumeration via response timing.
var dummyHash, _ = HashPassword("unmask-login-timing-equalizer")

// DummyCheckPassword runs a verify against the fixed dummy hash and discards the
// result.  Call it on the user-not-found login path to match the cost of a real
// CheckPassword.
func DummyCheckPassword(plain string) { _ = CheckPassword(dummyHash, plain) }

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
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return nil, err
	}
	return r.CreateWithHash(ctx, username, hash, role)
}

// CreateWithHash is Create but takes an already-argon2id-hashed password (PHC
// string) instead of plaintext.  The setup wizard hashes the operator password
// the moment it is entered and never keeps the plaintext (AUTH-7), so install
// commits the stored hash directly.
func (r *Repository) CreateWithHash(ctx context.Context, username, passwordHash, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is empty")
	}
	if !IsValidRole(role) {
		return nil, fmt.Errorf("invalid role: %q", role)
	}
	if passwordHash == "" {
		return nil, errors.New("password hash is empty")
	}
	row := db.User{Username: username, PasswordHash: passwordHash, Role: role, CreatedAt: time.Now()}
	if err := r.DB.Gorm.WithContext(ctx).Select("Username", "PasswordHash", "Role").Create(&row).Error; err != nil {
		// Both SQLite and MariaDB produce driver-specific UNIQUE violation
		// messages, so do a coarse string check.
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
		`SELECT id, username, password_hash, role, email, alert_opt_out, disabled, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE username = ?`, username)
	return scanUser(row)
}

// GetByID: load the user from the session cookie payload (= user_id).
func (r *Repository) GetByID(ctx context.Context, id int64) (*User, error) {
	row := r.DB.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, disabled, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE id = ?`, id)
	return scanUser(row)
}

// List: for the superadmin user-management UI.  Ascending by username.
func (r *Repository) List(ctx context.Context) ([]*User, error) {
	rows, err := r.DB.QueryContext(ctx,
		`SELECT id, username, password_hash, role, email, alert_opt_out, disabled, reset_token, reset_token_expires_at, created_at, last_login
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
	res := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Update("password_hash", hash)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// otherActiveSuperadmins counts ENABLED superadmins besides userID.  The
// last-superadmin guards count against this, not a raw role count: a disabled
// superadmin cannot administer anything, so it must not keep the guard
// satisfied while the only working superadmin is removed, demoted or
// suspended.
func (r *Repository) otherActiveSuperadmins(ctx context.Context, userID int64) (int, error) {
	var n int
	err := r.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unmask_user WHERE role = ? AND disabled = 0 AND id <> ?`,
		RoleSuperadmin, userID).Scan(&n)
	return n, err
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
		n, err := r.otherActiveSuperadmins(ctx, userID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastSuperadmin
		}
	}
	return r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Update("role", newRole).Error
}

// SetDisabled: suspend or restore an account.  Suspending the last enabled
// superadmin is refused — it would leave nobody able to administer the
// install (the same lock-out the delete / demote guards exist for).
func (r *Repository) SetDisabled(ctx context.Context, userID int64, disabled bool) error {
	cur, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if disabled && cur.Role == RoleSuperadmin {
		n, err := r.otherActiveSuperadmins(ctx, userID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastSuperadmin
		}
	}
	v := 0
	if disabled {
		v = 1
	}
	res := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Update("disabled", v)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete: remove the user.  The last superadmin cannot be removed.
func (r *Repository) Delete(ctx context.Context, userID int64) error {
	cur, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if cur.Role == RoleSuperadmin {
		n, err := r.otherActiveSuperadmins(ctx, userID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastSuperadmin
		}
	}
	return r.DB.Gorm.WithContext(ctx).Where("id = ?", userID).Delete(&db.User{}).Error
}

// TouchLastLogin: update last_login on successful authentication.
// best-effort (= login itself succeeds even if this fails).
func (r *Repository) TouchLastLogin(ctx context.Context, userID int64) {
	_ = r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Update("last_login", time.Now()).Error
}

// scanUser: scanner that handles both QueryRow / Rows.  Includes
// email/alert_opt_out/reset_*.
func scanUser(r interface {
	Scan(...any) error
}) (*User, error) {
	var u User
	var optOut, disabled int64
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Email, &optOut, &disabled, &u.ResetToken, &u.ResetTokenExpiresAt, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.AlertOptOut = optOut != 0
	u.Disabled = disabled != 0
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
	res := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Updates(map[string]any{"email": emailVal, "alert_opt_out": optOut})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
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
	res := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Updates(map[string]any{"reset_token": token, "reset_token_expires_at": expires})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
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
		`SELECT id, username, password_hash, role, email, alert_opt_out, disabled, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE reset_token = ?`, token)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	if !u.ResetTokenExpiresAt.Valid || u.ResetTokenExpiresAt.Int64 < time.Now().Unix() {
		// Expired.  Wipe the token and fail.
		_ = clearResetToken(ctx, r, u.ID)
		return nil, ErrNotFound
	}
	// Consume atomically by (id, token): once the winner nulls the token, a
	// concurrent redeem of the same token updates 0 rows, so the token is truly
	// one-shot even under the SELECT-then-UPDATE race (DB-7).
	res := r.DB.Gorm.WithContext(ctx).Model(&db.User{}).
		Where("id = ? AND reset_token = ?", u.ID, token).
		Updates(map[string]any{"reset_token": nil, "reset_token_expires_at": nil})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrNotFound // lost the race; the token was already consumed
	}
	return u, nil
}

// clearResetToken nulls out reset_token + reset_token_expires_at in one update.
func clearResetToken(ctx context.Context, r *Repository, userID int64) error {
	return r.DB.Gorm.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).
		Updates(map[string]any{"reset_token": nil, "reset_token_expires_at": nil}).Error
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
		`SELECT id, username, password_hash, role, email, alert_opt_out, disabled, reset_token, reset_token_expires_at, created_at, last_login
		 FROM unmask_user WHERE email = ? ORDER BY id LIMIT 1`, email)
	return scanUser(row)
}

// AlertRecipients: load the users that should receive alert mail
// (= email present + alert_opt_out=0 + role in superadmin/admin).
// Called from the notifier.  viewers do not receive notifications.
func (r *Repository) AlertRecipients(ctx context.Context) ([]string, error) {
	rows, err := r.DB.QueryContext(ctx,
		`SELECT email FROM unmask_user
		 WHERE email IS NOT NULL AND email <> '' AND alert_opt_out = 0 AND disabled = 0 AND role IN (?, ?)`,
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
