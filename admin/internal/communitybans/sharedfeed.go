package communitybans

import (
	"log"
	"net/http"
	"sync"
	"time"

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

	// Logger: optional.  nil → log package default.
	Logger *log.Logger

	mu sync.Mutex // serializes concurrent submit / pull / register

	// cachedDoc: last successful hub feed kept in memory so the browse page
	// can render without re-fetching on every request and without a disk
	// cache.  Replaces the legacy /etc/unmask/community-bans-doc.json file
	// (= state, not config; never read by nginx).  Written by Pull(); read
	// by GetCachedDoc().  RWMutex so concurrent UI reads don't serialise.
	docMu     sync.RWMutex
	cachedDoc FeedDocument
}

// GetCachedDoc returns a copy of the last feed pulled from the hub.  Empty
// document (= GeneratedAt == 0) when nothing has been pulled yet (= startup
// before the first Pull, or subscribe_mode=off).
func (c *Client) GetCachedDoc() FeedDocument {
	c.docMu.RLock()
	defer c.docMu.RUnlock()
	return c.cachedDoc
}

// setCachedDoc replaces the in-memory feed snapshot.  Internal: Pull() calls
// this after a successful fetch; nothing else mutates the cache.
func (c *Client) setCachedDoc(d FeedDocument) {
	c.docMu.Lock()
	c.cachedDoc = d
	c.docMu.Unlock()
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
