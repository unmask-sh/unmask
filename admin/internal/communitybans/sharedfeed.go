package communitybans

import (
	"log"
	"net/http"
	"sync"
	"sync/atomic"
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

	// matcher: the enforceable feed, as the daemon sees it.  Loaded from the
	// map files nginx includes (see matcher.go) so the forward-auth decision
	// and ServeChallenge enforce exactly what the native path enforces.
	// Refreshed whenever those files are rewritten, and once at Run() start
	// so a cold boot with an unreachable hub still enforces the last pull.
	matcher atomic.Pointer[Matcher]
}

// resolveMapDir returns the directory holding community-bans-*.map for this
// install: the client override first (= tests), then the operator setting,
// then the nginx output dir, then the packaged default.  One resolver so the
// placeholder writer, the pull writer and the matcher loader can never look at
// different directories.
func (c *Client) resolveMapDir(cur settings.Settings) string {
	for _, d := range []string{c.MapDir, cur.CommunityBans.MapDir, cur.Nginx.OutputDir} {
		if d != "" {
			return d
		}
	}
	return "/var/lib/unmask/nginx"
}

// Matcher returns the current enforceable-feed matcher.  Never nil-unsafe:
// the zero value reads as an empty matcher that never hits.
func (c *Client) Matcher() *Matcher { return c.matcher.Load() }

// reloadMatcher re-reads the map files in dir into the in-memory matcher.
// Called right after the files are (re)written and once at startup -- the
// files are the single enforcement artifact, so this is the only way the
// daemon's view can be anything other than nginx's view.
func (c *Client) reloadMatcher(dir string) {
	m, err := LoadMatcher(dir)
	if err != nil {
		c.logf("communitybans: load matcher from %s: %v", dir, err)
		return
	}
	c.matcher.Store(m)
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
