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
// subscribe_enabled=false (= returns nil, nil).  On success, updates
// settings.CommunityBans.LastPulledAt / Entries.
func (c *Client) Pull(ctx context.Context) (FeedDocument, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cur := c.SettingsGetter()
	mode := cur.CommunityBans.ResolvedSubscribeMode()

	// Resolve the output dir up front -- needed for both the off (= clear)
	// and active (= write) paths.  c.MapDir wins; else settings fall-backs.
	mapDir := c.MapDir
	if mapDir == "" {
		mapDir = cur.CommunityBans.MapDir
	}
	if mapDir == "" {
		mapDir = cur.Nginx.OutputDir
	}
	if mapDir == "" {
		mapDir = "/etc/unmask"
	}

	// off: stop pulling AND clear the map + doc so stale entries don't keep
	// enforcing / showing.  Empty map files keep nginx's include valid.
	if mode == settings.SubscribeOff {
		empty := FeedDocument{GeneratedAt: time.Now().Unix(), Version: 2}
		_ = WriteMapFiles(empty, mapDir)
		_ = WriteDocument(empty, mapDir)
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
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return FeedDocument{}, fmt.Errorf("decode feed: %w", err)
	}

	// Always write the browse doc (= both fetch and fetch_apply show the list).
	if err := WriteDocument(doc, mapDir); err != nil {
		c.logf("communitybans: write doc: %v", err)
	}

	// Enforcement is fetch_apply-only.  In "fetch" mode the maps are written
	// empty so nginx sees the entries for browsing (via the doc) but never
	// challenges traffic, and a previous fetch_apply's maps are cleared.
	autoApplied := 0
	if cur.CommunityBans.ApplyActive() {
		// Whitelisted-crawler guard: never enforce a feed entry whose IP
		// falls in a bypass preset / bypass-IP range (= Googlebot, Bingbot,
		// GPTBot official ranges, internal LBs).  The challenge path already
		// exempts $is_bypass_ip, but the auto-ban path writes into the local
		// ban file, which the native plugin reads with no bypass awareness --
		// so a community report on a search-engine IP would otherwise lock it
		// to CAPTCHA.  Strip those entries before they reach the map files or
		// the local ban list; the browse doc above keeps them for visibility.
		enforce := doc
		if kept, skipped := excludeBypassedEntries(doc.Entries, NewBypassMatcher(cur)); skipped > 0 {
			enforce.Entries = kept
			c.logf("communitybans: excluded %d whitelisted-crawler entr(ies) from enforcement (search-engine accident guard)", skipped)
		}
		if err := WriteMapFiles(enforce, mapDir); err != nil {
			return doc, fmt.Errorf("write map files: %w", err)
		}
		// Auto-apply: copy promoted high-score entries into the local BAN
		// list (opt-in via AutoBanMinScore).
		autoApplied = c.applyAutoBans(ctx, enforce, cur.CommunityBans.AutoBanMinScore, cur.CommunityBans.AutoBanAction)
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
	if autoApplied > 0 {
		c.logf("communitybans: auto-applied %d promoted entr(ies) into local BAN list", autoApplied)
	}
	c.logf("communitybans: pulled %d entries from %s", cnt, redactURL(url))
	return doc, nil
}

// applyAutoBans: walk promoted entries scoring >= minScore and copy them into
// the local BAN list with source=community_bans.  Returns the count applied
// (= for log output).  Skips when BanMgr is nil or minScore <= 0 (= the
// operator has opted out of automatic local-list propagation).
func (c *Client) applyAutoBans(ctx context.Context, doc FeedDocument, minScore int, action string) int {
	if c.BanMgr == nil || minScore <= 0 {
		return 0
	}
	if action == "" {
		action = "captcha_only"
	}
	now := time.Now().Unix()
	n := 0
	for _, e := range doc.Entries {
		if !e.Promoted || e.Score < minScore {
			continue
		}
		if e.ExpiresAt > 0 && e.ExpiresAt < now {
			continue
		}
		if e.IP == "" {
			// ja4_only entries -- BanMgr is IP-keyed.  These keep map-only enforcement.
			continue
		}
		reason := fmt.Sprintf("auto: community_bans hub (score=%d)", e.Score)
		c.BanMgr.AddFromHub(ctx, e.IP, e.JA4, reason, action, e.ExpiresAt)
		n++
	}
	return n
}

// redactURL: drops the query string for log output (= prevents token leaks).
func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i > 0 {
		return u[:i]
	}
	return u
}
