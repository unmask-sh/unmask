package handlers

// retentionProjection: the retention tab's disk-fill forecast, derived from
// stats the tab already collects.  Zero value = not enough data to show.
type retentionProjection struct {
	Show      bool
	Retention int   // days the projection used (0 = retain forever)
	PerDay    int64 // observed DB growth, bytes/day
	// Projected: steady-state DB size at Retention (0 when Retention==0 --
	// unbounded growth has no steady state).
	Projected int64
	DiskFree  int64 // free bytes on the DB volume (0 = unknown / not local)
	// FillRisk: the projection says the volume fills -- either the remaining
	// growth toward steady state exceeds ~all the free space, or retention is
	// infinite and the free space lasts under fillRiskHorizonDays at the
	// current rate.
	FillRisk   bool
	DaysToFull int // rough days until the volume fills (0 = n/a)
}

// fillRiskHorizonDays: with infinite retention the DB fills eventually by
// definition; the warning fires only when "eventually" is inside this horizon,
// so a small install with years of headroom is not nagged.
const fillRiskHorizonDays = 90

// projectRetentionDisk builds the forecast.  Linear on the observed span:
// unmask_event dominates the file on every measured install and the
// fixed-window aggregates grow toward their own 32-day cap on the same
// timescale, so fileSize x retention/span is an honest first-order model of the
// steady state.  Requires at least a full day of history for a stable rate.
// now/oldestTS are unix seconds; dbSize/diskFree bytes.
func projectRetentionDisk(dbSize, oldestTS, now int64, retention int, diskFree int64) retentionProjection {
	p := retentionProjection{Retention: retention, DiskFree: diskFree}
	if dbSize <= 0 || oldestTS <= 0 || now <= oldestTS {
		return p
	}
	spanDays := float64(now-oldestTS) / 86400
	if spanDays < 1 {
		return p
	}
	p.Show = true
	perDay := float64(dbSize) / spanDays
	p.PerDay = int64(perDay)
	var growth float64 // bytes still to be added before steady state
	if retention > 0 {
		if spanDays >= float64(retention) {
			p.Projected = dbSize // steady state reached: the prune keeps it here
		} else {
			p.Projected = int64(perDay * float64(retention))
			growth = float64(p.Projected - dbSize)
		}
	}
	if diskFree > 0 && perDay > 0 {
		days := float64(diskFree) / perDay
		switch {
		case retention <= 0:
			p.DaysToFull = int(days)
			p.FillRisk = days <= fillRiskHorizonDays
		case growth >= float64(diskFree)*0.9:
			p.FillRisk = true
			p.DaysToFull = int(days)
		}
	}
	return p
}
