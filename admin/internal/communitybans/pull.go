package communitybans

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Pull: fetches the feed JSON and regenerates the map file.  Skipped when
// subscribe_mode is off (= returns nil, nil).  On success, updates
// settings.CommunityBans.LastPulledAt / Entries.
func (c *Client) Pull(ctx context.Context) (FeedDocument, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cur := c.SettingsGetter()
	mode := cur.CommunityBans.ResolvedSubscribeMode()

	// Resolve the output dir up front -- needed for both the off (= clear)
	// and active (= write) paths.  c.MapDir wins; else settings fall-backs.
	// Default = Nginx.OutputDir (= /var/lib/unmask/nginx/), which is already
	// the nginx-specific dir; no further sub-directory is needed.
	mapDir := c.MapDir
	if mapDir == "" {
		mapDir = cur.CommunityBans.MapDir
	}
	if mapDir == "" {
		mapDir = cur.Nginx.OutputDir
		if mapDir == "" {
			mapDir = "/var/lib/unmask/nginx"
		}
	}

	// off: stop pulling AND clear the map + in-memory doc cache so stale
	// entries don't keep enforcing / showing.  Empty map files keep nginx's
	// include valid.
	if mode == settings.SubscribeOff {
		empty := FeedDocument{GeneratedAt: time.Now().Unix(), Version: 2}
		_ = WriteMapFiles(empty, mapDir)
		c.setCachedDoc(empty)
		return FeedDocument{}, nil
	}

	url := cur.CommunityBans.ResolvedFeedURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FeedDocument{}, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return FeedDocument{}, fmt.Errorf("get feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return FeedDocument{}, fmt.Errorf("feed: status %d: %s", resp.StatusCode, string(raw))
	}

	var doc FeedDocument
	// Cap the body so a compromised / mis-configured hub can't drive admin
	// into an OOM by streaming a giant JSON (pull runs every hour on cron).
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return FeedDocument{}, fmt.Errorf("decode feed: %w", err)
	}

	// Always cache the browse doc in memory (= both fetch and fetch_apply
	// show the list).  Replaces the legacy /etc/unmask/community-bans-doc.json
	// file -- nginx never read it, and admin restart is uncommon enough that
	// memory-only caching is fine (= a stale UI for one Pull cycle on cold
	// start is acceptable; the hub is back within the hour anyway).
	c.setCachedDoc(doc)

	// Enforcement is fetch_apply-only.  In "fetch" mode the maps are written
	// empty so nginx sees the entries for browsing (via the doc) but never
	// challenges traffic, and a previous fetch_apply's maps are cleared.
	//
	// Community entries are intentionally NOT copied into the local
	// unmask_ban table -- the nginx maps are the sole enforcement surface
	// for community feeds.  "BAN 管理" stays a list of *this install's own*
	// decisions (= manual / honeypot / 5-axes).  The "共有 BAN" tab is the
	// single UI for browsing what arrived from the hub.
	if cur.CommunityBans.ApplyActive() {
		// Whitelisted-crawler guard: never enforce a feed entry whose IP
		// falls in a bypass preset / bypass-IP range (= Googlebot, Bingbot,
		// GPTBot official ranges, internal LBs).  The challenge path already
		// exempts $is_bypass_ip, but writing such an IP into the map would
		// still lock search-engine traffic to CAPTCHA on the native plugin
		// path -- strip those entries before the map files; the browse doc
		// above keeps them for visibility.
		enforce := doc
		if kept, skipped := excludeBypassedEntries(doc.Entries, NewBypassMatcher(cur)); skipped > 0 {
			enforce.Entries = kept
			c.logf("communitybans: excluded %d whitelisted-crawler entr(ies) from enforcement (search-engine accident guard)", skipped)
		}
		// Local mutes: install-specific opt-outs from the "共有 BAN" tab.
		// Bypassed entries are dropped first (= secure default for crawler
		// IPs) so the mute count below reflects only operator-initiated
		// silences.
		if kept, skipped := excludeMutedEntries(enforce.Entries, cur.CommunityBans.LocalMutes); skipped > 0 {
			enforce.Entries = kept
			c.logf("communitybans: muted %d entr(ies) per LocalMutes", skipped)
		}
		if err := WriteMapFiles(enforce, mapDir); err != nil {
			return doc, fmt.Errorf("write map files: %w", err)
		}
	} else {
		empty := FeedDocument{GeneratedAt: time.Now().Unix(), Version: doc.Version}
		if err := WriteMapFiles(empty, mapDir); err != nil {
			return doc, fmt.Errorf("clear map files: %w", err)
		}
	}

	now := time.Now().Unix()
	cnt := len(doc.Entries)
	if err := c.SettingsUpdate(func(s *settings.Settings) {
		s.CommunityBans.LastPulledAt = now
		s.CommunityBans.Entries = cnt
	}); err != nil {
		c.logf("communitybans: persist pull state: %v", err)
	}
	c.logf("communitybans: pulled %d entries from %s", cnt, redactURL(url))
	return doc, nil
}

// redactURL: strips secret-bearing parts before logging a feed URL -- the query
// string and any userinfo (scheme://user:token@host).  The path is kept for
// debuggability; if a future feed URL carries a token in the path, mask it here
// too (L-3).
func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i > 0 {
		u = u[:i]
	}
	if at := strings.IndexByte(u, '@'); at > 0 {
		if p := strings.Index(u, "://"); p >= 0 && p+3 < at {
			u = u[:p+3] + u[at+1:]
		}
	}
	return u
}
