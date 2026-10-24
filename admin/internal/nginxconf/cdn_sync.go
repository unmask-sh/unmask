package nginxconf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/cdn"
)

// cdnURL: the CDN egress list sits beside the bypass-IP document on the hub
// -- same directory, same signing step -- like the relay list.
func (s *Sync) cdnURL() string {
	u := s.hubURL()
	i := strings.LastIndex(u, "/")
	if i < 0 {
		return ""
	}
	return u[:i+1] + cdn.FileName
}

func (s *Sync) cdnLastModifiedPath() string {
	return filepath.Join(s.dir(), ".cdn-last-modified")
}

// pullCDN fetches the CDN egress list, checks its detached signature by the
// rule the bypass-IP document is held to, and installs it (cdn.Ingest: no
// older document, none that lost half its prefixes).  Reports whether a new
// list went in.  A hub that does not carry the list answers 404: logged,
// and the list built into the binary stays in use.
func (s *Sync) pullCDN(ctx context.Context) (bool, error) {
	url := s.cdnURL()
	if url == "" {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	lmPath := s.cdnLastModifiedPath()
	// Ask for a copy only when the one in use came from this file: a restart
	// that found none on disk must not be answered 304.
	if cdn.Current() != nil {
		if b, err := os.ReadFile(lmPath); err == nil && len(b) > 0 {
			req.Header.Set("If-Modified-Since", string(b))
		}
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	case http.StatusNotFound:
		return false, fmt.Errorf("%s: not on this hub (the list built into this binary stays in use)", url)
	default:
		return false, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return false, fmt.Errorf("read body: %w", err)
	}
	if _, err := s.verifyDetachedSigAt(ctx, url, body); err != nil {
		return false, err
	}
	t, err := cdn.Ingest(s.dir(), body)
	if err != nil {
		return false, err
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		_ = os.WriteFile(lmPath, []byte(lm), 0o644)
	}
	s.logf("cdn list: %d prefixes of %d CDNs (generated %s)", t.Prefixes, t.Vendors, t.GeneratedAt.Format("2006-01-02 15:04Z"))
	return true, nil
}
