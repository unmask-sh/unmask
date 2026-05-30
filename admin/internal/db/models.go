package db

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
}

func (Ban) TableName() string { return "unmask_ban" }
