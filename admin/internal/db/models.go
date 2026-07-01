package db

import "time"

// GORM models for admin tables.
//
// Admin's schema is owned by migrate.go (raw CREATE TABLE / ALTER), so these
// models map onto the existing tables for the query layer only -- there is no
// AutoMigrate here.  Column tags mirror migrate.go exactly; int64 timestamp
// columns are app-managed (autoCreateTime/autoUpdateTime:false) so GORM never
// rewrites them.

// Ban: a row of unmask_ban (the persistent BAN list).  The unique key
// (ip, ja4) is enforced by the schema; upserts target it via
// clause.OnConflict, which renders portably on sqlite (ON CONFLICT) and
// mariadb (ON DUPLICATE KEY UPDATE).
type Ban struct {
	ID        int64  `gorm:"primaryKey;autoIncrement"`
	IP        string `gorm:"column:ip;not null"`
	JA4       string `gorm:"column:ja4;not null"`
	Source    string `gorm:"column:source;not null"`
	Reason    string `gorm:"column:reason"`
	BannedAt  int64  `gorm:"column:banned_at;not null;autoCreateTime:false"`
	ExpiresAt int64  `gorm:"column:expires_at;not null;default:0"`
	BannedBy  string `gorm:"column:banned_by"`
	Action    string `gorm:"column:action;not null;default:''"`
	// Scope decides what the C plugin matches against at request time:
	//   "ip_ja4"   exact (ip, ja4) tuple -- both columns must equal the visitor's
	//   "ja4_only" any IP with this JA4 (= residential / mobile network bots)
	//   "ip_only"  any JA4 from this IP (= compromised host / scraper farm)
	// The IP / JA4 columns keep full operator-entered info regardless of scope,
	// so flipping scope later (= the dropdown in the BAN modal) does not lose
	// the context.  flush() emits a different file-line shape per scope.
	Scope string `gorm:"column:scope;not null;default:'ip_ja4'"`
}

func (Ban) TableName() string { return "unmask_ban" }

// User: a row of unmask_user.  Pointer fields (Email / ResetToken /
// ResetTokenExpiresAt / LastLogin) map to NULL-able columns -- GORM persists
// nil as SQL NULL, so the "clear reset_token" path stays one Update call on
// both drivers (no need for a separate UPDATE ... = NULL branch).
//
// CreatedAt has a CURRENT_TIMESTAMP default on both backends; mark it
// autoCreateTime:false so GORM never tries to assign its own zero value when
// the column is omitted.
type User struct {
	ID                  int64      `gorm:"primaryKey;autoIncrement"`
	Username            string     `gorm:"column:username;not null;uniqueIndex"`
	PasswordHash        string     `gorm:"column:password_hash;not null"`
	Role                string     `gorm:"column:role;not null"`
	Email               *string    `gorm:"column:email"`
	AlertOptOut         int        `gorm:"column:alert_opt_out;not null;default:0"`
	ResetToken          *string    `gorm:"column:reset_token"`
	ResetTokenExpiresAt *int64     `gorm:"column:reset_token_expires_at"`
	CreatedAt           time.Time  `gorm:"column:created_at;not null;autoCreateTime:false"`
	LastLogin           *time.Time `gorm:"column:last_login"`
}

func (User) TableName() string { return "unmask_user" }

// UserAudit: a row of unmask_user_audit.  At has a CURRENT_TIMESTAMP default on
// both backends; leaving it the zero value lets the DB stamp it.
type UserAudit struct {
	ID       int64     `gorm:"primaryKey;autoIncrement"`
	UserID   *int64    `gorm:"column:user_id"`
	Username string    `gorm:"column:username;not null"`
	Action   string    `gorm:"column:action;not null"`
	Target   *string   `gorm:"column:target"`
	Detail   *string   `gorm:"column:detail"`
	At       time.Time `gorm:"column:at;not null;autoCreateTime:false"`
}

func (UserAudit) TableName() string { return "unmask_user_audit" }

// RebindLineage caps how many times -- and how fast -- a single solved
// challenge (identified by the random lineage id in its _bvj cookie) can be
// silently re-bound to a new client IP.  Without it, a stolen _bv/_bvj pair
// whose ASN happens to match the victim's (same carrier, or a residential proxy
// in the same AS) could be re-bound onto unboundedly many IPs.  Keyed by
// lineage so the cap holds fleet-wide on a shared DB and survives a daemon
// restart (an in-memory counter would reset to zero each restart, handing an
// attacker a fresh budget).  Pruned by the hourly goroutine once stale.
type RebindLineage struct {
	Lineage     string `gorm:"column:lineage;primaryKey"`
	Host        string `gorm:"column:host;not null;default:''"`
	Count       int    `gorm:"column:count;not null;default:0"`        // lifetime rebinds
	WindowStart int64  `gorm:"column:window_start;not null;default:0"` // unix sec, rate-window anchor
	WindowCount int    `gorm:"column:window_count;not null;default:0"` // rebinds in the current window
	UpdatedAt   int64  `gorm:"column:updated_at;not null;default:0"`   // unix sec, for prune
}

func (RebindLineage) TableName() string { return "unmask_rebind_lineage" }
