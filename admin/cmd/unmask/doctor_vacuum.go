package main

import (
	"context"
	"fmt"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// checkVacuum: free space inside the database file, and the last compaction.
//
// The retention prune deletes rows; SQLite keeps the pages they held and
// reuses them, so the file never shrinks, and the table ends up scattered
// through it -- every read that walks it seeks where it would have streamed.
// Past a quarter of the file and a gigabyte, `unmask db-vacuum` gives the
// space back and lays the tables out again with the daemon serving (see
// internal/db/vacuum.go), and this says so with what it would need.
func checkVacuum(conn *db.DB, addOK, addWarn func(t, m string)) {
	if conn.Driver != db.DriverSQLite {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if rec, ok, err := conn.LoadVacuum(ctx); err == nil && ok {
		switch {
		case conn.VacuumAlive(rec, time.Now()):
			addOK("DB compaction", fmt.Sprintf("running since %s (by %s, pid %d)",
				time.Unix(rec.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), rec.By, rec.PID))
			return
		case rec.State == db.VacuumFailed && time.Since(time.Unix(rec.EndedAt, 0)) < 7*24*time.Hour:
			addWarn("DB compaction", fmt.Sprintf("the last run failed at %s: %s",
				time.Unix(rec.EndedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), rec.Err))
		}
	}
	p, err := conn.PlanVacuum(ctx)
	if err != nil {
		addWarn("DB compaction", fmt.Sprintf("could not work out the free space (%v)", err))
		return
	}
	free := fmt.Sprintf("%s of the %s file is free space", humanBytesCLI(p.Reclaim), humanBytesCLI(p.FileBytes))
	if p.Reclaim < 1<<30 || p.Reclaim*4 < p.FileBytes {
		addOK("DB compaction", free)
		return
	}
	disk := "unknown"
	if p.DiskFree >= 0 {
		disk = humanBytesCLI(p.DiskFree)
	}
	addWarn("DB compaction", fmt.Sprintf("%s -- the file does not shrink by itself, and a scattered table slows every full read. "+
		"`unmask db-vacuum` compacts it with the daemon serving (or the retention tab's button): about %s, "+
		"%s of disk while it runs (%s free), up to %d events held in memory meanwhile; `-plan` shows the figures",
		free, db.EstimateRange(p.EstLow, p.EstHigh), humanBytesCLI(p.DiskNeed), disk, p.HeldEvents))
}
