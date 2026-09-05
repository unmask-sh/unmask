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

// AdvisorDismiss: a row of unmask_advisor_dismiss — an advisor ban candidate
// the operator explicitly rejected.  The advisor page filters these out so a
// judged-and-declined suggestion does not nag on every visit.  (target_type,
// target) is unique in the schema; writes upsert onto it.
type AdvisorDismiss struct {
	ID          int64  `gorm:"primaryKey;autoIncrement"`
	TargetType  string `gorm:"column:target_type;not null"` // "ip" | "ja4"
	Target      string `gorm:"column:target;not null"`
	DismissedBy string `gorm:"column:dismissed_by"`
	DismissedAt int64  `gorm:"column:dismissed_at;not null;autoCreateTime:false"`
}

func (AdvisorDismiss) TableName() string { return "unmask_advisor_dismiss" }

// AdvisorNotified: a row of unmask_advisor_notified — an advisor candidate a
// scheduled digest has already announced.  The scheduler subtracts these so
// each digest reports what is new; rows age out (see the scheduler) so a
// target that goes quiet and returns can be announced again.
type AdvisorNotified struct {
	ID         int64  `gorm:"primaryKey;autoIncrement"`
	TargetType string `gorm:"column:target_type;not null"` // "ip" | "ja4"
	Target     string `gorm:"column:target;not null"`
	NotifiedAt int64  `gorm:"column:notified_at;not null;autoCreateTime:false"`
}

func (AdvisorNotified) TableName() string { return "unmask_advisor_notified" }

// AdvisorRun: a row of unmask_advisor_run — one model call the advisor made
// (or tried to).  The page sums the last 30 days into "N requests, X in /
// Y out"; the last answer itself lives in AdvisorResult.
type AdvisorRun struct {
	ID        int64  `gorm:"primaryKey;autoIncrement"`
	RanAt     int64  `gorm:"column:ran_at;not null;autoCreateTime:false"`
	ResultKey string `gorm:"column:result_key;not null"`
	Model     string `gorm:"column:model;not null"`
	Reviewed  int    `gorm:"column:reviewed;not null"`
	Kept      int    `gorm:"column:kept;not null"`
	InTokens  int    `gorm:"column:in_tokens;not null"`
	OutTokens int    `gorm:"column:out_tokens;not null"`
	Err       string `gorm:"column:err;not null"`
}

func (AdvisorRun) TableName() string { return "unmask_advisor_run" }

// AdvisorResult: a row of unmask_advisor_result — the model's last answer for
// one window (per provider / model / endpoint / language), kept so a restart
// does not turn a paid answer into "not asked yet".  Upserted on key_hash.
type AdvisorResult struct {
	KeyHash   string `gorm:"column:key_hash;primaryKey"`
	ResultKey string `gorm:"column:result_key;not null"`
	RanAt     int64  `gorm:"column:ran_at;not null;autoCreateTime:false"`
	Model     string `gorm:"column:model;not null"`
	Payload   string `gorm:"column:payload;not null"`
	Err       string `gorm:"column:err;not null"`
}

func (AdvisorResult) TableName() string { return "unmask_advisor_result" }

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
	Disabled            int        `gorm:"column:disabled;not null;default:0"`
	ResetToken          *string    `gorm:"column:reset_token"`
	ResetTokenExpiresAt *int64     `gorm:"column:reset_token_expires_at"`
	CreatedAt           time.Time  `gorm:"column:created_at;not null;autoCreateTime:false"`
	LastLogin           *time.Time `gorm:"column:last_login"`
}

func (User) TableName() string { return "unmask_user" }

// UserAudit: a row of unmask_user_audit.  At has a CURRENT_TIMESTAMP default on
// both backends; leaving it the zero value lets the DB stamp it.
type UserAudit struct {
	ID       int64   `gorm:"primaryKey;autoIncrement"`
	UserID   *int64  `gorm:"column:user_id"`
	Username string  `gorm:"column:username;not null"`
	Action   string  `gorm:"column:action;not null"`
	Target   *string `gorm:"column:target"`
	Detail   *string `gorm:"column:detail"`
	// IP: where the action came from.  Nil for rows written before the column
	// existed and for callers with no HTTP request behind them (CLI, cron).
	IP *string   `gorm:"column:ip"`
	At time.Time `gorm:"column:at;not null;autoCreateTime:false"`
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
