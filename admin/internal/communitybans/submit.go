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
)

// Submit: call asynchronously on BAN.  errors:
//   - if settings.CommunityBans.SubmitActive() is false, skip (= return nil)
//   - on empty token + failed inline register retry, return ErrNoToken (= retry later).
//   - server 4xx / 5xx is returned with the status code embedded.
//
// The caller invokes this in a goroutine, logs the returned err, and lets the
// BAN itself succeed regardless.
//
// Inline register on empty token: right after terms acceptance + flipping
// submit_enabled on (= before the startup Run-loop has fired its first
// register), a BAN used to fail with ErrNoToken.  So when the token is
// empty, we synchronously try Register() once, and if it succeeds, continue
// to submit.
func (c *Client) Submit(ctx context.Context, req SubmitRequest) error {
	cur := c.SettingsGetter()
	if !cur.CommunityBans.SubmitActive() {
		return nil
	}
	tok := strings.TrimSpace(cur.CommunityBans.Token)
	if tok == "" {
		if err := c.Register(ctx); err != nil {
			return fmt.Errorf("submit: inline register: %w", err)
		}
		cur = c.SettingsGetter()
		tok = strings.TrimSpace(cur.CommunityBans.Token)
		if tok == "" {
			return ErrNoToken
		}
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" {
		return errors.New("submit: ip is empty")
	}
	// Clamp comment to 280 chars.  Allow only single newlines (= server re-sanitizes).
	req.Comment = clampComment(req.Comment, 280)
	// Carry the install-wide country opt-in flag.  Default off so a fresh
	// install never leaks country to the hub until the operator opts in.
	req.PublishCountry = cur.CommunityBans.PublishCountry

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal submit: %w", err)
	}
	url := cur.CommunityBans.ResolvedSubmitURL()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", c.UserAgent)
	httpReq.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("post submit: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("submit: status %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

// ErrNoToken: sentinel returned by Submit when settings.CommunityBans.Token is empty.
var ErrNoToken = errors.New("communitybans: no token (= register first)")

func clampComment(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Collapse repeated newlines (= prevent layout breakage from stacked blank lines).
	s = strings.ReplaceAll(s, "\r\n", "\n")
	for strings.Contains(s, "\n\n") {
		s = strings.ReplaceAll(s, "\n\n", "\n")
	}
	if len(s) > n {
		// Truncate on rune boundary.
		r := []rune(s)
		if len(r) > n {
			r = r[:n]
		}
		s = string(r)
	}
	return s
}
