package nginxconf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// relayURL: the relay egress list sits beside the bypass-IP document on the
// hub -- same directory, same signing step.
func (s *Sync) relayURL() string {
	u := s.hubURL()
	i := strings.LastIndex(u, "/")
	if i < 0 {
		return ""
	}
	return u[:i+1] + relay.FileName
}

func (s *Sync) relayLastModifiedPath() string {
	return filepath.Join(s.dir(), ".relay-last-modified")
}

// pullRelay fetches the relay egress list, checks its detached signature by
// the rule the bypass-IP document is held to (required from the published
// hub), and installs it (relay.Ingest: no older document, none that lost
// half its prefixes).  Reports whether a new list went in.  A hub of the
// operator's own that does not carry the list answers 404: logged, nothing
// changes.
func (s *Sync) pullRelay(ctx context.Context) (bool, error) {
	url := s.relayURL()
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
	lmPath := s.relayLastModifiedPath()
	// Ask for a copy only when the one in use came from this file: a restart
	// that found none on disk must not be answered 304.
	if relay.Current() != nil {
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
		return false, fmt.Errorf("%s: not on this hub", url)
	default:
		return false, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return false, fmt.Errorf("read body: %w", err)
	}
	if _, err := s.verifyDetachedSigAt(ctx, url, body); err != nil {
		return false, err
	}
	t, err := relay.Ingest(s.dir(), body)
	if err != nil {
		return false, err
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		_ = os.WriteFile(lmPath, []byte(lm), 0o644)
	}
	s.logf("relay list: %d prefixes in %d countries (generated %s)", t.Prefixes, t.Countries, t.GeneratedAt.Format("2006-01-02 15:04Z"))
	return true, nil
}

// PullRelayFromFile installs a relay egress list handed over as a file, for
// hosts that cannot reach the hub (the bypass-IP document's -file path).
// A sidecar signature is checked when present and required where the policy
// asks for it (fileSignatureRequired), as for that document.
func (s *Sync) PullRelayFromFile(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sig, serr := os.ReadFile(path + FeedSigSuffix); serr == nil {
		if _, verr := VerifyFeedSignatureKeyID(body, sig); verr != nil {
			return fmt.Errorf("feed signature: %w", verr)
		}
	} else if s.fileSignatureRequired() {
		return fmt.Errorf("feed signature required but %s%s is missing", path, FeedSigSuffix)
	}
	t, err := relay.Ingest(s.dir(), body)
	if err != nil {
		return err
	}
	s.logf("relay list: %d prefixes in %d countries from %s", t.Prefixes, t.Countries, path)
	if s.RenderFunc != nil {
		if err := s.RenderFunc(); err != nil {
			s.logf("relay list: render after import failed: %v", err)
		}
	}
	return nil
}
