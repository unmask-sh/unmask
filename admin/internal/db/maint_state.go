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

// MaintAggregatePrune is the task name the hourly prune of the aggregate
// tables records under.
const MaintAggregatePrune = "aggregate_prune"

// AggregatePruneRecord is the aggregate prune's last-run record.  doctor reads
// it to tell a table that is past its window because no prune has completed
// yet (an upgrade from a version that did not prune it, minutes ago) from one
// the prune runs over and does not trim.
type AggregatePruneRecord struct {
	// StartedAt / CompletedAt: unix seconds of the last run, and of the last
	// run in which every table was trimmed.
	StartedAt   int64 `json:"started_at"`
	CompletedAt int64 `json:"completed_at,omitempty"`
	// Failed: the tables whose prune failed in the last run, with why.
	Failed map[string]string `json:"failed,omitempty"`
}

// MaintSchemaUpdate is the task name a schema update (the migrations the
// daemon left for the operator, applied by `unmask migrate`) records under.
const MaintSchemaUpdate = "schema_update"

// Schema update states.
const (
	SchemaUpdateRunning   = "running"
	SchemaUpdateDone      = "done"
	SchemaUpdateFailed    = "failed"
	SchemaUpdateCancelled = "cancelled"
)

// SchemaUpdateRecord is the last schema update: written before the first
// statement runs (the update holds the write lock while it builds, so there is
// no writing progress during it) and again when it ends.
type SchemaUpdateRecord struct {
	State string   `json:"state"`
	Items []string `json:"items"` // the migrations this run applies
	// Host / PID: where it runs, so a reader can tell a run that is still
	// going from one whose process is gone.
	Host string `json:"host,omitempty"`
	PID  int    `json:"pid,omitempty"`
	// By: who started it -- an admin's username, or "cli".
	By        string `json:"by,omitempty"`
	StartedAt int64  `json:"started_at"`
	EndedAt   int64  `json:"ended_at,omitempty"`
	// EstLowSec / EstHighSec: the estimate shown when it started.
	EstLowSec  int `json:"est_low_s,omitempty"`
	EstHighSec int `json:"est_high_s,omitempty"`
	// Seconds: how long it took (ended runs).
	Seconds float64 `json:"seconds,omitempty"`
	Err     string  `json:"err,omitempty"`
	// Stage: what a running run is doing now -- SchemaStageIndex while a
	// migration is applied (Current names it, Done counts the ones before
	// it), SchemaStageCheckpoint while the new index is copied out of the
	// write-ahead log, SchemaStageFinish while what follows the migrations
	// runs.  StageAt: when it began.  Without these the admin UI could say
	// only how long the run had taken (a large install, 2026-10-06: over
	// twenty minutes of "updating" after an index built in under half a
	// minute, and no way to tell what was going on).
	Stage   string `json:"stage,omitempty"`
	Current string `json:"current,omitempty"`
	Done    int    `json:"done,omitempty"`
	StageAt int64  `json:"stage_at,omitempty"`
}

// The stages of a schema update run (SchemaUpdateRecord.Stage).
const (
	SchemaStageIndex      = "index"
	SchemaStageCheckpoint = "checkpoint"
	SchemaStageFinish     = "finish"
)

// MaintSchemaRate is the task name this host's measured index build rate is
// kept under.
const MaintSchemaRate = "schema_rate"

// SchemaRateRecord is how fast this host built an index the last time it built
// one over a table large enough to measure by.  Estimates use it in place of
// the built-in range, which has to cover every disk there is.
type SchemaRateRecord struct {
	MicrosPerRow float64 `json:"us_per_row"`
	Rows         int64   `json:"rows"`
	MeasuredAt   int64   `json:"measured_at"`
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
