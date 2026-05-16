package sharedfeed

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
// settings.SharedFeed.LastPulledAt / Entries.
func (c *Client) Pull(ctx context.Context) (FeedDocument, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cur := c.SettingsGetter()
	if !cur.SharedFeed.SubscribeEnabled {
		return FeedDocument{}, nil
	}

	url := cur.SharedFeed.ResolvedFeedURL()
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

	// Resolve the output dir.  c.MapDir wins; if empty, fall back to settings.Nginx.OutputDir.
	mapDir := c.MapDir
	if mapDir == "" {
		mapDir = cur.SharedFeed.MapDir
	}
	if mapDir == "" {
		mapDir = cur.Nginx.OutputDir
	}
	if mapDir == "" {
		mapDir = "/etc/unmask"
	}

	if err := WriteMapFiles(doc, mapDir); err != nil {
		return doc, fmt.Errorf("write map files: %w", err)
	}
	if err := WriteDocument(doc, mapDir); err != nil {
		// A doc write failure only stales the browse page; it doesn't affect behavior
		// (= the map itself is written, so CAPTCHA enforcement still works).  Warn only.
		c.logf("sharedfeed: write doc: %v", err)
	}

	now := time.Now().Unix()
	cnt := len(doc.Entries)
	if err := c.SettingsUpdate(func(s *settings.Settings) {
		s.SharedFeed.LastPulledAt = now
		s.SharedFeed.Entries = cnt
	}); err != nil {
		c.logf("sharedfeed: persist pull state: %v", err)
	}
	c.logf("sharedfeed: pulled %d entries from %s", cnt, redactURL(url))
	return doc, nil
}

// redactURL: drops the query string for log output (= prevents token leaks).
func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i > 0 {
		return u[:i]
	}
	return u
}
