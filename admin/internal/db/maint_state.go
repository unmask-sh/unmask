package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MaintState: a row of unmask_maint_state -- the last-run record of one timed
// maintenance task, so doctor and the admin can say whether it is keeping up
// without reading the daemon log.
type MaintState struct {
	Name      string `gorm:"column:name;primaryKey"`
	Value     string `gorm:"column:value;not null"`
	UpdatedAt int64  `gorm:"column:updated_at;not null;autoUpdateTime:false"`
}

func (MaintState) TableName() string { return "unmask_maint_state" }

// MaintEventsPrune is the task name the retention prune records under.
const MaintEventsPrune = "events_prune"

// PruneRecord is the events prune's last-run record (the JSON in
// unmask_maint_state.value).
type PruneRecord struct {
	// StartedAt / EndedAt: unix seconds of the last run.
	StartedAt int64 `json:"started_at"`
	EndedAt   int64 `json:"ended_at,omitempty"`
	// CompletedAt: unix seconds of the last run that ended with no row older
	// than the cutoff left -- the number doctor judges "keeping up" by.
	CompletedAt int64 `json:"completed_at,omitempty"`
	// Retention: the retention (days) the run used.
	Retention int `json:"retention"`
	// Deleted / Chunks / BusyRetries / Seconds: what the last run did.
	Deleted     int64   `json:"deleted"`
	Chunks      int     `json:"chunks"`
	BusyRetries int     `json:"busy_retries"`
	Seconds     float64 `json:"seconds"`
	// Err: how the last run ended when it did not finish ("" = finished or
	// still running; a deadline reads as "budget reached").
	Err string `json:"err,omitempty"`
}

// SaveMaintState upserts a task's record.
func (d *DB) SaveMaintState(ctx context.Context, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	row := MaintState{Name: name, Value: string(b), UpdatedAt: time.Now().Unix()}
	return d.Gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&row).Error
}

// LoadMaintState reads a task's record into v.  Returns (false, nil) when the
// task has no record yet.
func (d *DB) LoadMaintState(ctx context.Context, name string, v any) (bool, error) {
	var row MaintState
	err := d.Gorm.WithContext(ctx).Where("name = ?", name).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(row.Value), v)
}
