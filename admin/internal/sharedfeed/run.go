package sharedfeed

import (
	"context"
	"time"
)

// Run: blocking loop that 1) registers + does the initial pull at startup,
// 2) re-pulls every interval, 3) exits on ctx.Done().  Intended to be called in
// a goroutine.
//
// interval <= 0 falls back to 1h (= 3600s).  No back-off on failure (= retried
// at the next interval).
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	cur := c.SettingsGetter()
	// register only when either submit or subscribe is ON
	if cur.SharedFeed.SubmitEnabled || cur.SharedFeed.SubscribeEnabled {
		if err := c.Register(ctx); err != nil {
			c.logf("sharedfeed: register: %v", err)
		}
	}
	// Initial pull (= only runs in earnest when subscribe is ON)
	if _, err := c.Pull(ctx); err != nil {
		c.logf("sharedfeed: initial pull: %v", err)
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
			if (cur.SharedFeed.SubmitEnabled || cur.SharedFeed.SubscribeEnabled) && cur.SharedFeed.Token == "" {
				if err := c.Register(ctx); err != nil {
					c.logf("sharedfeed: register (later): %v", err)
				}
			}
			if _, err := c.Pull(ctx); err != nil {
				c.logf("sharedfeed: pull: %v", err)
			}
		}
	}
}
