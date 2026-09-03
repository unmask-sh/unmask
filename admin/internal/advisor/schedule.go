// schedule.go — the scheduled digest pass (Phase 3 of the advisor design).
//
// The advisor page only helps an operator who thinks to open it.  This runs
// the same deterministic engine on a timer and hands anything NEW to the alert
// channels the install already has, so a scanner that shows up at 03:00 is on
// record by morning instead of waiting to be noticed.
//
// Three deliberate choices:
//
//   - It does not call the model.  A background job should not spend the
//     operator's tokens while nobody is watching; the reasoning is added when
//     they open the page.
//   - It reports what is NEW.  Targets already announced are subtracted, so
//     the digest does not repeat yesterday's list every night until someone
//     acts on it.  Rows age out, so a target that goes quiet and comes back
//     can earn a fresh mention.
//   - It only wakes someone for candidates carrying more than one signal
//     (score >= NotifyMinScore, default 6).  A single scanner-path hit belongs
//     on the page, not in an alert.
package advisor

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// notifiedTTL: how long an announced target stays suppressed.  Long enough
// that an unresolved candidate is not re-announced nightly, short enough that
// a returning scanner is news again.
const notifiedTTL = 14 * 24 * time.Hour

// containedAlertServes: a client the challenge already contains is only worth
// an alert once serving it that many challenges in a day is a cost in itself.
const containedAlertServes = 300

// Digest is what one scheduled pass found worth announcing.
type Digest struct {
	New   []Candidate // candidates above the score floor, not announced before
	Total int         // every candidate in the window, for context
}

// Deps is what the scheduler needs from the rest of the daemon.  Passing them
// in (rather than importing settings/notifier machinery here) keeps this
// package free of import cycles and makes the pass testable with fakes.
type Deps struct {
	DB   *db.DB
	Geo  *ipgeo.Reader
	Cfg  func() settings.AIAdvisorConfig
	Excl func(ctx context.Context) (Exclusions, error)
	// Notify delivers the digest.  Nil disables delivery (the pass still runs
	// and records what it saw, which keeps the first real digest from being a
	// flood of everything ever seen).
	Notify func(d Digest)
}

// RunSchedule runs the digest pass on the configured interval until ctx ends.
// It re-reads the config every tick, so switching the schedule on or off in
// the web UI takes effect without a restart.
func RunSchedule(ctx context.Context, deps Deps) {
	if deps.DB == nil || deps.Cfg == nil {
		return
	}
	// A short settling delay: at startup the daemon is still opening the DB,
	// migrating and warming caches, and the first window is not interesting
	// enough to compete with that.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}

	for {
		cfg := deps.Cfg()
		if cfg.NotifyActive() {
			if err := RunDigestOnce(ctx, deps); err != nil && ctx.Err() == nil {
				log.Printf("advisor digest: %v", err)
			}
		}
		// Re-read the interval each time so a change applies from the next
		// tick; when the schedule is off, look again in an hour.
		wait := cfg.ResolvedNotifyInterval()
		if !cfg.NotifyActive() {
			wait = time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// RunDigestOnce performs a single pass: extract candidates, subtract the ones
// already announced, record the rest, and hand them to Notify.
func RunDigestOnce(ctx context.Context, deps Deps) error {
	cfg := deps.Cfg()
	excl := Exclusions{}
	if deps.Excl != nil {
		var err error
		if excl, err = deps.Excl(ctx); err != nil {
			return fmt.Errorf("exclusions: %w", err)
		}
	}
	// The digest looks at the same window the page defaults to.
	cands, err := Candidates(ctx, deps.DB, deps.Geo, excl, Options{WindowMinutes: 24 * 60})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := pruneNotified(ctx, deps.DB, now.Add(-notifiedTTL).Unix()); err != nil {
		return fmt.Errorf("prune notified: %w", err)
	}
	seen, err := loadNotified(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("load notified: %w", err)
	}

	minScore := cfg.ResolvedNotifyMinScore()
	var fresh []Candidate
	for _, c := range cands {
		if c.Score < minScore || seen[notifiedKey(c.Type, c.Target)] {
			continue
		}
		// A contained client is not news: the challenge already stops it.
		// It earns an alert only when its volume is itself the cost.
		if c.Contained && c.Serves < containedAlertServes {
			continue
		}
		fresh = append(fresh, c)
	}
	if len(fresh) == 0 {
		return nil
	}
	if err := recordNotified(ctx, deps.DB, fresh, now.Unix()); err != nil {
		return fmt.Errorf("record notified: %w", err)
	}
	if deps.Notify != nil {
		deps.Notify(Digest{New: fresh, Total: len(cands)})
	}
	return nil
}

func notifiedKey(typ, target string) string { return typ + "\x00" + target }

func loadNotified(ctx context.Context, conn *db.DB) (map[string]bool, error) {
	var rows []db.AdvisorNotified
	if err := conn.Gorm.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[notifiedKey(r.TargetType, r.Target)] = true
	}
	return out, nil
}

func recordNotified(ctx context.Context, conn *db.DB, cands []Candidate, at int64) error {
	rows := make([]db.AdvisorNotified, 0, len(cands))
	for _, c := range cands {
		rows = append(rows, db.AdvisorNotified{TargetType: c.Type, Target: c.Target, NotifiedAt: at})
	}
	return conn.Gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "target_type"}, {Name: "target"}},
		DoUpdates: clause.AssignmentColumns([]string{"notified_at"}),
	}).Create(&rows).Error
}

func pruneNotified(ctx context.Context, conn *db.DB, before int64) error {
	return conn.Gorm.WithContext(ctx).
		Where("notified_at < ?", before).
		Delete(&db.AdvisorNotified{}).Error
}

// FormatDigest renders the plain-text body carried by the alert channels.  It
// leads with what an operator needs to decide whether to get up: how many are
// new, and what the loudest ones did.
func FormatDigest(d Digest, adminURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d new ban candidate(s) in the last 24h (%d candidate(s) in total).\n\n",
		len(d.New), d.Total)

	rows := append([]Candidate(nil), d.New...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Score > rows[j].Score })
	for i, c := range rows {
		if i == 5 {
			fmt.Fprintf(&b, "... and %d more.\n", len(rows)-5)
			break
		}
		ids := make([]string, 0, len(c.Signals))
		for _, s := range c.Signals {
			ids = append(ids, s.ID)
		}
		state := "PASSING the challenge"
		if c.Contained {
			state = "contained by the challenge"
		}
		fmt.Fprintf(&b, "- %s %s [%s] -- %s\n", c.Type, c.Target, strings.Join(ids, ", "), state)
		fmt.Fprintf(&b, "    %d challenges served, %d passed", c.Serves, c.Passes)
		if c.ScannerHits > 0 {
			fmt.Fprintf(&b, ", %d scanner-path hits", c.ScannerHits)
		}
		if c.DistinctIPs > 0 {
			fmt.Fprintf(&b, ", %d addresses", c.DistinctIPs)
		}
		if c.ASNOrg != "" {
			fmt.Fprintf(&b, " (%s)", c.ASNOrg)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nNothing has been blocked: these are suggestions.\n")
	if adminURL != "" {
		fmt.Fprintf(&b, "Review them at %s\n", adminURL)
	}
	return b.String()
}
