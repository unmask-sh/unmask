package handlers

import (
	"context"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// RunOverBlockMonitor samples the challenge funnel on a ticker and trips the
// over-block circuit breaker when visitors are stuck at the challenge -- the
// shape of the 2026-06-08 production incident, which over-blocked real users
// for ~14h before anyone noticed.  On a trip it alerts (and, when
// AutoPassthrough is set, flips serveBotChallenge to passthrough so visitors
// get through); it clears and alerts again when the signal recovers.
//
// Config is read live each tick, so thresholds can be tuned (or the breaker
// disabled) without a restart.  Blocks until ctx is cancelled.
func (h *Handler) RunOverBlockMonitor(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for tick := 0; ; tick++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer safe.Recover("over-block-monitor") // a panic here must not kill the daemon
				h.checkOverBlock(ctx, tick%longWindowEvery == 0)
			}()
		}
	}
}

// longWindowEvery: the long window is read every this many ticks (minutes).
// It is there for a quiet site, where minutes do not matter, and reading an
// hour of the log every minute does not pay.
const longWindowEvery = 5

// checkOverBlock performs one sample-and-transition of the breaker.  readLong
// also reads the long window; otherwise its last reading stands.
func (h *Handler) checkOverBlock(ctx context.Context, readLong bool) {
	st := h.snapshotSettings()
	cfg := st.OverBlock
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
	short, err := events.StuckVisitors(qctx, h.DB, cfg.WindowMinutesResolved(), true)
	if err != nil {
		log.Printf("over-block monitor: %v", err)
		return
	}
	long, hasLong := h.overBlockLong.Load(), false
	if lw := cfg.LongWindowMinutesResolved(); lw > short.Minutes {
		if readLong || long == nil {
			r, err := events.StuckVisitors(qctx, h.DB, lw, false)
			if err != nil {
				log.Printf("over-block monitor (%dm): %v", lw, err)
			} else {
				long = &r
				h.overBlockLong.Store(long)
			}
		}
		hasLong = long != nil
	}

	report := short
	overBlocking := evalOverBlock(cfg, short)
	if !overBlocking && hasLong && evalOverBlock(cfg, *long) {
		overBlocking, report = true, *long
	}
	tripped := h.overBlockTripped.Load()
	switch {
	case overBlocking && !tripped:
		if report.Minutes != short.Minutes {
			// Tripped on the long window, read without the volume: the mail
			// says how many challenges the hour saw, so count them now.
			if r, err := events.StuckVisitors(qctx, h.DB, report.Minutes, true); err == nil {
				report = r
			}
		}
		h.overBlockTripped.Store(true)
		log.Printf("over-block TRIPPED: %d of %d addresses that ran the challenge are stuck (%d%%; %d re-challenged after passing, %d failing verification) over %dm (auto_passthrough=%v)",
			report.Stuck, report.Loaders, report.StuckShare(), report.Rechallenged, report.VerifyFailed, report.Minutes, cfg.AutoPassthrough)
		h.Notifier.OverBlock(overBlockReport(true, report, cfg.MinStuckIPsResolved(), cfg.StuckPercentResolved(), cfg.AutoPassthrough, adminURL(st)))
	case !overBlocking && tripped:
		h.overBlockTripped.Store(false)
		log.Printf("over-block cleared: %d of %d addresses that ran the challenge are stuck (%d%%) over %dm",
			short.Stuck, short.Loaders, short.StuckShare(), short.Minutes)
		h.Notifier.OverBlock(overBlockReport(false, short, cfg.MinStuckIPsResolved(), cfg.StuckPercentResolved(), cfg.AutoPassthrough, adminURL(st)))
	}
}

// evalOverBlock is the pure decision: are visitors stuck in this window?  At
// least MinStuckIPs addresses, and at least StuckPercent of those that ran the
// challenge.
//
// Both, because each alone fires on an ordinary day.  A busy site has a
// handful of stuck addresses in any ten minutes (a browser that drops
// cookies, a crawler that runs the script but keeps no cookie jar) -- a few
// percent of those that ran the challenge; a quiet one can have one stuck
// visitor in three.  A loop makes nearly all of them stuck.
func evalOverBlock(cfg overBlockThresholds, r events.StuckReport) bool {
	return r.Stuck >= cfg.MinStuckIPsResolved() && r.StuckShare() >= cfg.StuckPercentResolved()
}

// overBlockThresholds is the slice of OverBlockConfig evalOverBlock needs (an
// interface keeps the test from importing the full settings type).
type overBlockThresholds interface {
	MinStuckIPsResolved() int
	StuckPercentResolved() int
}

// overBlockReport turns a window's reading into the notifier's report.
func overBlockReport(tripped bool, r events.StuckReport, minStuck, minPct int, autoPass bool, admin string) notifier.OverBlockReport {
	out := notifier.OverBlockReport{
		Tripped: tripped, Minutes: r.Minutes,
		Stuck: r.Stuck, Loaders: r.Loaders, StuckPct: r.StuckShare(),
		Rechallenged: r.Rechallenged, VerifyFailed: r.VerifyFailed,
		Passed: r.Passed, Serves: r.Serves, ServeIPs: r.ServeIPs, Loads: r.Loads,
		MinStuck: minStuck, MinPct: minPct, AutoPassthrough: autoPass, AdminURL: admin,
	}
	for _, e := range r.Examples {
		out.Examples = append(out.Examples, notifier.OverBlockExample{
			IP: e.IP, Site: e.Site, Path: e.Path, Rechallenged: e.Rechallenged, VerifyFailed: e.VerifyFailed,
		})
	}
	return out
}

// adminURL is the admin's address for the links an alert carries: the first
// host nginx.admin_allowed_hosts names, and the base path.  "" when the list
// names no single host -- the mail then says where to look.  Not a request's
// Host header, as a password-reset link uses: there is no request behind an
// alert.
func adminURL(s settings.Settings) string {
	for _, e := range settings.EnabledValues(s.Nginx.AdminAllowedHosts, s.Nginx.AdminAllowedHostsDisabled) {
		e = strings.TrimSpace(e)
		host := ""
		switch settings.PatternModeOf(e) {
		case settings.ModeExact, settings.ModeContains, settings.ModeSubdomain:
			host = settings.PatternText(e)
		default: // a regex that spells out one host
			if plainHostRE.MatchString(e) {
				host = e
			}
		}
		if plainHostRE.MatchString(host) {
			return "https://" + strings.ToLower(host) + s.Server.BasePath
		}
	}
	return ""
}

var plainHostRE = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

// overBlockPassthrough reports whether the breaker is tripped AND configured to
// auto-passthrough -- i.e. serveBotChallenge should let visitors through to cap
// the blast radius of a challenge loop.  Read on the challenge hot path.
func (h *Handler) overBlockPassthrough() bool {
	return h.overBlockTripped.Load() && h.snapshotSettings().OverBlock.AutoPassthrough
}

// OverBlockHealth is the breaker's live signal for the overview's trip banner
// (only rendered when Tripped).
type OverBlockHealth struct {
	Tripped bool
	// Stuck of Loaders (StuckPct percent) could not get through over WindowMin.
	Stuck, Loaders, StuckPct int
	WindowMin                int
	AutoPass                 bool
}

// OverBlockHealth samples the breaker's current signal for the overview banner.
// It uses the breaker's own global, fixed-window view (not the dashboard's site
// / time filter), so the banner matches what the monitor acts on.  Read only
// when the breaker is tripped: the banner is not shown otherwise.
func (h *Handler) OverBlockHealth(ctx context.Context) (OverBlockHealth, error) {
	cfg := h.snapshotSettings().OverBlock
	hh := OverBlockHealth{
		Tripped:   h.overBlockTripped.Load(),
		WindowMin: cfg.WindowMinutesResolved(),
		AutoPass:  cfg.AutoPassthrough,
	}
	if !hh.Tripped {
		return hh, nil
	}
	r, err := events.StuckVisitors(ctx, h.DB, hh.WindowMin, false)
	if err != nil {
		return hh, err
	}
	if !evalOverBlock(cfg, r) {
		// Tripped on the long window: show that one.
		if lr := h.overBlockLong.Load(); lr != nil {
			r = *lr
		}
	}
	hh.Stuck, hh.Loaders, hh.StuckPct, hh.WindowMin = r.Stuck, r.Loaders, r.StuckShare(), r.Minutes
	return hh, nil
}
