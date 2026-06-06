package communitybans

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Hub-operator client: queries the hub-side endpoints introduced in the hub
// commit "operator endpoints for reviewing pending removal requests".  Only
// the operator running the hub itself enables this (= sets OperatorEndpoint +
// OperatorTokenFile in CommunityBans); on every other install the screen
// stays hidden so submitting a bug report doesn't pretend it's available.

// RemovalRow mirrors feedserver.RemovalRow on the hub side.  We re-declare it
// here rather than import the hub to keep the admin binary free of the hub
// module.
type RemovalRow struct {
	ID         int64  `json:"id"`
	TargetKind string `json:"target_kind"`
	Target     string `json:"target"`
	Reason     string `json:"reason"`
	Contact    string `json:"contact"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"created_at"`
	HandledAt  int64  `json:"handled_at"`
}

// OperatorClient: thin HTTP client.  endpoint is the base URL (= the hub root
// before /api/feed/operator/...), tokenFile is the path the operator bearer
// is read from on every call so rotation is hot.
type OperatorClient struct {
	Endpoint   string
	TokenFile  string
	HTTPClient *http.Client
}

// IsConfigured: true when both the endpoint and the token file are set.  The
// admin UI hides the operator screen when false.
func (c *OperatorClient) IsConfigured() bool {
	return c != nil && strings.TrimSpace(c.Endpoint) != "" && strings.TrimSpace(c.TokenFile) != ""
}

// Token reads the bearer from disk on every call.  Empty file / read error =
// empty token -> the hub will 401.
func (c *OperatorClient) token() (string, error) {
	b, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", fmt.Errorf("read operator token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *OperatorClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *OperatorClient) url(path string) string {
	base := strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	return base + path
}

// ListRemovals fetches removal requests filtered by status ("pending",
// "done", "rejected", "all"; empty = pending).  Returns the rows in the
// order the hub provides them (most-recent-first).
func (c *OperatorClient) ListRemovals(ctx context.Context, status string) ([]RemovalRow, error) {
	if !c.IsConfigured() {
		return nil, errors.New("operator client not configured")
	}
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	u := c.url("/api/feed/operator/removals")
	if status != "" {
		u += "?status=" + status
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hub status %d: %s", resp.StatusCode, string(raw))
	}
	var body struct {
		Rows []RemovalRow `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode rows: %w", err)
	}
	return body.Rows, nil
}

// PatchRemoval marks the row done or rejected.  Returns nil on 204; an error
// describing the hub's response otherwise (409 conflict / 404 / etc.).
func (c *OperatorClient) PatchRemoval(ctx context.Context, id int64, status string) error {
	if !c.IsConfigured() {
		return errors.New("operator client not configured")
	}
	if status != "done" && status != "rejected" {
		return errors.New(`status must be "done" or "rejected"`)
	}
	tok, err := c.token()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"status": status})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		c.url(fmt.Sprintf("/api/feed/operator/removal/%d", id)),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("hub status %d: %s", resp.StatusCode, string(raw))
}
