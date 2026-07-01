package handlers

import (
	"context"
	"log"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// RunOverBlockMonitor samples the challenge funnel on a ticker and trips the
// over-block circuit breaker when the same visitors are being re-challenged
// instead of passing -- the shape of the 2026-06-08 tool1-jp incident, which
// over-blocked real users for ~14h before anyone noticed.  On a trip it alerts
// (and, when AutoPassthrough is set, flips serveBotChallenge to passthrough so
// visitors get through); it clears and alerts again when the signal recovers.
//
// Config is read live each tick, so thresholds can be tuned (or the breaker
// disabled) without a restart.  Blocks until ctx is cancelled.
func (h *Handler) RunOverBlockMonitor(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer safe.Recover("over-block-monitor") // a panic here must not kill the daemon
				h.checkOverBlock(ctx)
			}()
		}
	}
}

// checkOverBlock performs one sample-and-transition of the breaker.
func (h *Handler) checkOverBlock(ctx context.Context) {
	cfg := h.snapshotSettings().OverBlock
	if cfg.Disabled {
		// Operator opted out: drop any tripped state so it doesn't latch (and
		// auto-passthrough recovers on the next request).
		if h.overBlockTripped.Swap(false) {
			log.Printf("over-block breaker disabled; cleared tripped state")
		}
		return
	}

	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	serves, ips, err := events.OverBlockStats(qctx, h.DB, cfg.WindowMinutesResolved())
	if err != nil {
		log.Printf("over-block monitor: %v", err)
		return
	}
	tripped, overBlocking, ratio := evalOverBlock(cfg, serves, ips, h.overBlockTripped.Load())

	switch {
	case overBlocking && !tripped:
		h.overBlockTripped.Store(true)
		log.Printf("over-block TRIPPED: %d serves / %d IPs = %.1f/IP over %dm (auto_passthrough=%v)",
			serves, ips, ratio, cfg.WindowMinutesResolved(), cfg.AutoPassthrough)
		h.Notifier.OverBlock(true, serves, ips, ratio, cfg.AutoPassthrough)
	case !overBlocking && tripped:
		h.overBlockTripped.Store(false)
		log.Printf("over-block cleared: %d serves / %d IPs = %.1f/IP over %dm",
			serves, ips, ratio, cfg.WindowMinutesResolved())
		h.Notifier.OverBlock(false, serves, ips, ratio, cfg.AutoPassthrough)
	}
}

// evalOverBlock is the pure decision: given the config, the sampled serve/IP
// counts and the current tripped state, return (tripped, overBlocking, ratio).
// overBlocking requires both enough volume and a high re-serve ratio (= the
// same IPs being challenged again and again).  Split out so it is unit-testable
// without a DB or a ticker.
func evalOverBlock(cfg overBlockThresholds, serves, ips int, tripped bool) (bool, bool, float64) {
	ratio := 0.0
	if ips > 0 {
		ratio = float64(serves) / float64(ips)
	}
	overBlocking := serves >= cfg.MinServesResolved() && ratio >= float64(cfg.MaxServesPerIPResolved())
	return tripped, overBlocking, ratio
}

// overBlockThresholds is the slice of OverBlockConfig evalOverBlock needs (an
// interface keeps the test from importing the full settings type).
type overBlockThresholds interface {
	MinServesResolved() int
	MaxServesPerIPResolved() int
}

// overBlockPassthrough reports whether the breaker is tripped AND configured to
// auto-passthrough -- i.e. serveBotChallenge should let visitors through to cap
// the blast radius of a challenge loop.  Read on the challenge hot path.
func (h *Handler) overBlockPassthrough() bool {
	return h.overBlockTripped.Load() && h.snapshotSettings().OverBlock.AutoPassthrough
}

// OverBlockHealth is the breaker's live signal for the overview's trip banner
// (only rendered when Tripped).
type OverBlockHealth struct {
	Tripped   bool
	Serves    int
	IPs       int
	Ratio     float64 // serves / IPs over the window
	Threshold int     // MaxServesPerIP -- Ratio at/above this trips
	WindowMin int
	AutoPass  bool
}

// OverBlockHealth samples the breaker's current signal for the overview banner.
// It uses the breaker's own global, fixed-window view (not the dashboard's site
// / time filter), so the banner matches exactly what the monitor acts on.
func (h *Handler) OverBlockHealth(ctx context.Context) (OverBlockHealth, error) {
	cfg := h.snapshotSettings().OverBlock
	hh := OverBlockHealth{
		Tripped:   h.overBlockTripped.Load(),
		Threshold: cfg.MaxServesPerIPResolved(),
		WindowMin: cfg.WindowMinutesResolved(),
		AutoPass:  cfg.AutoPassthrough,
	}
	serves, ips, err := events.OverBlockStats(ctx, h.DB, hh.WindowMin)
	if err != nil {
		return hh, err
	}
	hh.Serves, hh.IPs = serves, ips
	if ips > 0 {
		hh.Ratio = float64(serves) / float64(ips)
	}
	return hh, nil
}
