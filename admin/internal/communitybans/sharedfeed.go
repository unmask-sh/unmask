package communitybans

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Client: API surface for register / submit / pull.
//
// Concurrency-safe: each method grabs the mutex it needs.  SettingsGetter /
// SettingsUpdate are assumed to be already serialised by the caller via
// settingsMu (= matches the handler-side usage).
type Client struct {
	// HTTPClient: overridable (= stubbed in tests).  nil → default with 10s timeout.
	HTTPClient *http.Client

	// UserAgent: shared User-Agent header for submit / pull / register.
	UserAgent string

	// SettingsGetter: returns the snapshot at call time.
	SettingsGetter func() settings.Settings

	// SettingsUpdate: callback that persists token / LastPulledAt / Entries.
	// The closure is expected to perform settings.Save + handler.Settings swap.
	SettingsUpdate func(func(*settings.Settings)) error

	// MapDir: output dir for community-bans-*.map.  Empty → settings.Nginx.OutputDir.
	MapDir string

	// BanMgr: optional.  When set, Pull() auto-adds promoted entries scoring
	// >= settings.CommunityBans.AutoBanMinScore into the local BAN list via
	// BanMgr.AddFromHub.  nil = disabled (= map files are the only output).
	BanMgr *ban.Manager

	// Logger: optional.  nil → log package default.
	Logger *log.Logger

	mu sync.Mutex // serializes concurrent submit / pull / register
}

// httpClient: if HTTPClient field is nil, build and return one on the fly.
func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// logf: fall back to the standard log if Logger is nil.
func (c *Client) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}
