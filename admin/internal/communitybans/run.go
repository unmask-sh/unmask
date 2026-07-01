package communitybans

import (
	"context"
	"time"
)

// PullInterval is the fixed cadence of the community-bans feed pull loop.  It is
// the single source of truth shared by the daemon's Run() call site (main.go)
// and the admin UI's "next fetch" estimate (= LastPulledAt + PullInterval).
const PullInterval = time.Hour

// Run: blocking loop that 1) registers + does the initial pull at startup,
// 2) re-pulls every interval, 3) exits on ctx.Done().  Intended to be called in
// a goroutine.
//
// interval <= 0 falls back to 1h (= 3600s).  No back-off on failure (= retried
// at the next interval).
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = PullInterval
	}
	cur := c.SettingsGetter()
	// Lay down empty community-bans map placeholders up front -- before the
	// network-bound register/pull -- so a fresh install's `nginx -t` never aborts
	// on a dangling community-bans-*.map include while the first fetch is slow or
	// failing (hub unreachable / offline).  http.inc includes the maps only when
	// subscribe is active; placeholders are skipped when the maps already exist.
	if cur.CommunityBans.SubscribeActive() {
		md := c.MapDir
		if md == "" {
			md = cur.CommunityBans.MapDir
		}
		if md == "" {
			md = cur.Nginx.OutputDir
		}
		if md == "" {
			md = "/var/lib/unmask/nginx"
		}
		ensureMapPlaceholders(md)
	}
	// register only when either submit or subscribe is ON
	if cur.CommunityBans.SubmitEnabled || cur.CommunityBans.SubscribeActive() {
		if err := c.Register(ctx); err != nil {
			c.logf("communitybans: register: %v", err)
		}
	}
	// Backfill HN for pre-v2 tokens (= HN was empty before phase 1 derived it).
	// No-op once cached.  Single POST per cold start.
	if err := c.BackfillHN(ctx); err != nil {
		c.logf("communitybans: hn backfill: %v", err)
	}
	// Initial pull (= only runs in earnest when subscribe is ON)
	if _, err := c.Pull(ctx); err != nil {
		c.logf("communitybans: initial pull: %v", err)
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Late register if settings flipped to ON
			cur := c.SettingsGetter()
			if (cur.CommunityBans.SubmitEnabled || cur.CommunityBans.SubscribeActive()) && cur.CommunityBans.Token == "" {
				if err := c.Register(ctx); err != nil {
					c.logf("communitybans: register (later): %v", err)
				}
			}
			if _, err := c.Pull(ctx); err != nil {
				c.logf("communitybans: pull: %v", err)
			}
		}
	}
}
