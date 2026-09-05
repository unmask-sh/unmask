// runs.go — one model run per result key, detached from the click.
//
// The operator's click starts the run and comes straight back; the page polls
// and fills its rows in when the answer lands.  Detaching the run from the
// request means a reload, a closed tab or a proxy timeout no longer loses
// the answer (or the money it cost), and a second click while the first run
// is still out attaches to it instead of paying twice.
package advisor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// runTimeout bounds one run end to end: engine, pool, reverse DNS, model
// (providerTimeout, llm.go, is the model's share).  The click does not wait
// for it, so it only has to beat a hung run, not the operator's patience.
const runTimeout = 6 * time.Minute

// RunInfo describes a run in flight: when it started and, from the plan
// made before it started, which candidates were sent to the model and which
// kept their earlier review.  The page shows a spinner on the former and
// "kept" on the latter from the first moment.
type RunInfo struct {
	Since time.Time
	Sent  map[string]bool
	Kept  map[string]bool
}

var runs = struct {
	mu sync.Mutex
	m  map[string]RunInfo
}{m: map[string]RunInfo{}}

// Running reports whether a run for key is in flight, and what it is doing.
func Running(key string) (RunInfo, bool) {
	runs.mu.Lock()
	defer runs.mu.Unlock()
	info, ok := runs.m[key]
	return info, ok
}

// StartRun runs fn in the background and stores what it returns as the key's
// last result (in memory and, when conn is given, in unmask_advisor_result).
// It reports false, and starts nothing, when a run for key is already in
// flight.  info carries the plan; Since is stamped here.
func StartRun(conn *db.DB, key string, info RunInfo, fn func(ctx context.Context) Stored) bool {
	runs.mu.Lock()
	if _, busy := runs.m[key]; busy {
		runs.mu.Unlock()
		return false
	}
	info.Since = time.Now()
	runs.m[key] = info
	runs.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		defer func() {
			runs.mu.Lock()
			delete(runs.m, key)
			runs.mu.Unlock()
		}()
		st := func() (st Stored) {
			defer func() {
				if r := recover(); r != nil {
					st = Stored{ErrAt: time.Now(), Err: fmt.Sprintf("advisor run: %v", r)}
				}
			}()
			return fn(ctx)
		}()
		StoreLast(conn, key, st)
	}()
	return true
}
