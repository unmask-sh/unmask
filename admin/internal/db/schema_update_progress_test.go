package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A run keeps on record what it is doing -- the migration it is applying, the
// copy of the new index out of the write-ahead log, what follows -- so the
// admin UI can say more than how long it has taken (2026-10-06: over twenty
// minutes of "updating" after an index built in under half a minute, and
// nobody could tell what was going on).  The terminal hears the same, for what takes time.
func TestApplySchemaUpdateRecordsItsStage(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	if _, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// A slow host, so that the build is one worth announcing.
	if err := d.SaveMaintState(ctx, MaintSchemaRate, SchemaRateRecord{MicrosPerRow: 20000, Rows: 500000}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]SchemaUpdateRecord{}
	var lines []string
	logf := func(f string, a ...any) {
		line := fmt.Sprintf(f, a...)
		lines = append(lines, line)
		rec, _, _ := d.LoadSchemaUpdate(ctx)
		switch {
		case strings.Contains(line, "0032_event_ja4_index: building"):
			seen["index"] = rec
		case strings.Contains(line, "write-ahead log"):
			seen["checkpoint"] = rec
		}
	}
	res, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "h", By: "cli", Logf: logf,
		Finish: func(context.Context) error {
			seen["finish"], _, _ = d.LoadSchemaUpdate(ctx)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("applied %v", res.Applied)
	}
	if r := seen["index"]; r.Stage != SchemaStageIndex || r.Current != "0032_event_ja4_index" || r.Done != 0 || r.StageAt == 0 || r.State != SchemaUpdateRunning {
		t.Errorf("record while 0032 was built = %+v, want stage index on 0032 with none done", r)
	}
	if r := seen["checkpoint"]; r.Stage != SchemaStageCheckpoint || r.Done != 2 {
		t.Errorf("record while the log was checkpointed = %+v, want stage checkpoint, both done", r)
	}
	if r := seen["finish"]; r.Stage != SchemaStageFinish || r.Done != 2 {
		t.Errorf("record while Finish ran = %+v, want stage finish, both done", r)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"0032_event_ja4_index: building (1 of 2)", "0032_event_ja4_index: built in"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the terminal did not hear %q:\n%s", want, joined)
		}
	}
	if rec, _, _ := d.LoadSchemaUpdate(ctx); rec.State != SchemaUpdateDone {
		t.Errorf("record after = %+v, want done", rec)
	}
}

// The end of a run is recorded with a deadline taken out when it is written.
// One taken out before the work that follows the migrations expired while
// that work ran, so a run that finished stayed on record as running
// (2026-10-06: "could not record how the run ended: context deadline
// exceeded" after a Finish of over twenty minutes).
func TestApplySchemaUpdateRecordsItsEndAfterALongFinish(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	if _, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	old := schemaRecordTimeout
	schemaRecordTimeout = 200 * time.Millisecond
	defer func() { schemaRecordTimeout = old }()

	var lines []string
	res, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{Host: "h", By: "cli",
		Logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) },
		Finish: func(context.Context) error {
			time.Sleep(3 * schemaRecordTimeout)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("nothing applied")
	}
	rec, _, err := d.LoadSchemaUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != SchemaUpdateDone || rec.EndedAt == 0 {
		t.Errorf("record after a Finish longer than the record's deadline = %+v, want done with an end time", rec)
	}
	for _, l := range lines {
		if strings.Contains(l, "could not record") {
			t.Errorf("the run could not record itself: %q", l)
		}
	}
}

// What follows the migrations runs under the run's context: an interrupt
// stops it as it stops a build.  It used to get a context of its own, and a
// first SIGINT left it running until a SIGTERM ended the process (2026-09-29).
// The schema is applied by then, so the run is still on record as done.
func TestApplySchemaUpdateFinishHearsTheInterrupt(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	if _, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	heard := false
	res, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "h", By: "cli",
		Finish: func(c context.Context) error {
			cancel() // the operator's ^C, while it runs
			select {
			case <-c.Done():
				heard = true
				return nil
			case <-time.After(5 * time.Second):
				return nil
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !heard {
		t.Error("Finish did not hear the interrupt")
	}
	if len(res.Applied) == 0 {
		t.Fatal("nothing applied")
	}
	if rec, _, _ := d.LoadSchemaUpdate(context.Background()); rec.State != SchemaUpdateDone {
		t.Errorf("record after an interrupt in Finish = %+v, want done: the schema is applied", rec)
	}
}
