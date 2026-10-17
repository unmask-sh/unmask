package db

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestWritesHeldGuard: while HoldWrites is in effect, a write through gorm is
// refused at once with ErrWritesHeld -- it would otherwise wait out the busy
// timeout against the lock the schema update holds, and fail then.  Reads go
// on; the hold lifted, writes go through again.
func TestWritesHeldGuard(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "g.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	row := func(ip string) *Ban {
		return &Ban{IP: ip, JA4: "t13d_g", Source: "manual", BannedAt: time.Now().Unix(), Scope: "ip_ja4"}
	}
	if err := d.Gorm.Create(row("203.0.113.1")).Error; err != nil {
		t.Fatal(err)
	}

	d.HoldWrites(true)
	t0 := time.Now()
	if err := d.Gorm.Create(row("203.0.113.2")).Error; !errors.Is(err, ErrWritesHeld) {
		t.Errorf("create during a hold: %v, want ErrWritesHeld", err)
	}
	if err := d.Gorm.Model(&Ban{}).Where("ip = ?", "203.0.113.1").Update("reason", "x").Error; !errors.Is(err, ErrWritesHeld) {
		t.Errorf("update during a hold: %v, want ErrWritesHeld", err)
	}
	if err := d.Gorm.Where("ip = ?", "203.0.113.1").Delete(&Ban{}).Error; !errors.Is(err, ErrWritesHeld) {
		t.Errorf("delete during a hold: %v, want ErrWritesHeld", err)
	}
	if err := d.Gorm.Exec(`DELETE FROM unmask_ban`).Error; !errors.Is(err, ErrWritesHeld) {
		t.Errorf("exec during a hold: %v, want ErrWritesHeld", err)
	}
	if took := time.Since(t0); took > time.Second {
		t.Errorf("the refusals took %v; they must not wait for the lock", took)
	}
	var got []Ban
	if err := d.Gorm.Find(&got).Error; err != nil || len(got) != 1 {
		t.Errorf("a read during a hold: %v, %d row(s), want the one row", err, len(got))
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n); err != nil || n != 1 {
		t.Errorf("a raw read during a hold: %v, %d", err, n)
	}

	d.HoldWrites(false)
	if err := d.Gorm.Create(row("203.0.113.2")).Error; err != nil {
		t.Errorf("create after the hold: %v", err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n); err != nil || n != 2 {
		t.Errorf("rows after the hold: %v, %d, want 2", err, n)
	}
}
