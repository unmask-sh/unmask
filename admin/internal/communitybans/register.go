package communitybans

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Register: if no token is configured, hit the register endpoint to obtain one and persist it.
// If a token already exists, this is a no-op.  Network failures return an error, but the caller
// is expected to log it and continue without aborting startup (= subscribe / submit don't work
// without a token, but the LP /feed/ page guides the user to re-register).
func (c *Client) Register(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cur := c.SettingsGetter()
	if strings.TrimSpace(cur.CommunityBans.Token) != "" {
		return nil // already have a token
	}

	url := cur.CommunityBans.ResolvedRegisterURL()
	body, err := json.Marshal(RegisterRequest{
		UnmaskVersion:  cur.Nginx.SeenVersion,
		PublishCountry: cur.CommunityBans.PublishCountry,
	})
	if err != nil {
		return fmt.Errorf("marshal register: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("post register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("register: status %d: %s", resp.StatusCode, string(raw))
	}

	var rr RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return fmt.Errorf("decode register: %w", err)
	}
	tok := strings.TrimSpace(rr.Token)
	if tok == "" {
		return errors.New("register: empty token in response")
	}

	hn := strings.TrimSpace(rr.HN)
	if err := c.SettingsUpdate(func(s *settings.Settings) {
		s.CommunityBans.Token = tok
		s.CommunityBans.HN = hn
	}); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	c.logf("communitybans: registered new token (len=%d, hn=%q)", len(tok), hn)
	return nil
}
