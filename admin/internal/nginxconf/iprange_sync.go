// Sync the bypass-IP preset prefixes from the unmask.sh hub.
//
// The hub fetches the 10 upstream vendor JSONs (= Googlebot / Bingbot / OAI /
// etc.) once per day, validates them, and re-publishes a single aggregated
// document at https://unmask.sh/dl/feed/iprange/bypass-iprange-all.json.  Each
// install polls that single URL — not the upstream vendors directly — so:
//
//   - upstream vendors see 1 fetch/day from the hub, not N from each install
//   - schema breakage / 50%+ prefix drop is caught once at the hub and the
//     install keeps its previous override file (= fail-safe)
//   - the install only depends on unmask.sh hub being reachable; vendor
//     outages are absorbed at the hub
//
// Sync is best-effort: any fetch error keeps the previous override files in
// place, and the embed snapshot remains the ultimate fallback.
package nginxconf

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SyncDefaultHubURL: the canonical hub-aggregated document.
const SyncDefaultHubURL = "https://unmask.sh/dl/feed/iprange/bypass-iprange-all.json"

// SyncDefaultDir: the override dir.  Matches what SetOverrideDir consumes.
const SyncDefaultDir = "/var/lib/unmask/iprange"

// SyncDefaultInterval: 24h ± SyncJitter is applied per tick to avoid all
// installs hitting the hub at the same second.
const SyncDefaultInterval = 24 * time.Hour

// SyncJitter: random offset in [-SyncJitter, +SyncJitter] is added to each
// interval.  2h spreads N installs evenly across a day.
const SyncJitter = 2 * time.Hour

// SyncInitialDelay: wait this long after startup before the first fetch (=
// don't block cmdServe; let nginx-render etc. proceed first).
const SyncInitialDelay = 30 * time.Second

// AggregatedDoc: shape published at SyncDefaultHubURL.  schemaVersion is
// bumped on a breaking change so old clients can stop applying.
type AggregatedDoc struct {
	SchemaVersion int                         `json:"schemaVersion"`
	GeneratedAt   string                      `json:"generatedAt"`
	Sources       map[string]AggregatedSource `json:"sources"`
}

// AggregatedSource: per-source body.  Same shape as the vendor JSON
// (= iprangePayload) so we can write it back to the override dir verbatim.
type AggregatedSource struct {
	CreationTime string             `json:"creationTime"`
	Prefixes     []AggregatedPrefix `json:"prefixes"`
}

// AggregatedPrefix: one prefix entry.  Vendor JSONs use one of these two
// fields per object; we preserve the same shape so the disk file parses with
// the same iprangePayload struct.
type AggregatedPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
}

// Sync polls the hub on an interval and writes refreshed JSON to OverrideDir.
//
// Construct via NewSync(...) and call Start(ctx); the goroutine returns when
// ctx is cancelled.  Methods are safe to call concurrently; the goroutine
// serializes its own work.
type Sync struct {
	HubURL     string        // empty → SyncDefaultHubURL
	Dir        string        // empty → SyncDefaultDir
	Interval   time.Duration // 0 → SyncDefaultInterval
	HTTPClient *http.Client  // nil → 30s timeout
	UserAgent  string        // sent on every request
	Logger     *log.Logger   // nil → log default

	// RenderFunc: called after a successful pull writes at least one file.
	// Typically wired to a closure that calls nginxconf.Render(settings,
	// outDir, version) so http.inc / server.inc pick up the new prefixes.
	// Nil disables rendering (= operator runs `unmask render-nginx` manually).
	// nginx -s reload is intentionally NOT triggered here — the operator
	// keeps control of when nginx actually reloads.
	RenderFunc func() error

	// lastModified holds the previous response's Last-Modified header so we
	// can send If-Modified-Since on the next request and let the hub answer
	// 304 when the doc hasn't changed.  Persisted to disk under Dir so the
	// 304 path survives restarts.
	lastModified string

	// State observable by the settings UI.  stateMu serialises only the
	// state fields below; PullOnce's I/O isn't under the lock.
	stateMu      sync.Mutex
	lastSyncedAt time.Time
	lastError    string
	lastWrittenN int
}

// LastSyncedAt returns the time of the last successful pull (= even if it
// resulted in a 304 with zero writes).  Zero if no pull has succeeded yet.
func (s *Sync) LastSyncedAt() time.Time {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastSyncedAt
}

// LastError returns the most recent pull's error message, or "" on success
// or when no pull has happened yet.
func (s *Sync) LastError() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastError
}

// HubURLString returns the resolved hub URL (= for display in the UI).
func (s *Sync) HubURLString() string { return s.hubURL() }

func (s *Sync) recordSuccess(written int) {
	s.stateMu.Lock()
	s.lastSyncedAt = time.Now().UTC()
	s.lastError = ""
	s.lastWrittenN = written
	s.stateMu.Unlock()
}

func (s *Sync) recordError(err error) {
	s.stateMu.Lock()
	s.lastError = err.Error()
	s.stateMu.Unlock()
}

// NewSync returns a Sync with defaults filled in.
func NewSync() *Sync { return &Sync{} }

func (s *Sync) hubURL() string {
	if s.HubURL != "" {
		return s.HubURL
	}
	return SyncDefaultHubURL
}

func (s *Sync) dir() string {
	if s.Dir != "" {
		return s.Dir
	}
	return SyncDefaultDir
}

func (s *Sync) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return SyncDefaultInterval
}

func (s *Sync) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *Sync) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Start runs the sync loop until ctx is cancelled.  Registers the override
// dir up front so even before the first successful pull, any files already
// on disk (= left from a previous run) take precedence over the embed.
func (s *Sync) Start(ctx context.Context) {
	dir := s.dir()
	SetOverrideDir(dir)
	s.loadLastModified()

	// Wait SyncInitialDelay before the first fetch so cmdServe / nginx-render
	// can complete cleanly.  Cancel-aware.
	select {
	case <-ctx.Done():
		return
	case <-time.After(SyncInitialDelay):
	}

	for {
		if err := s.PullOnce(ctx); err != nil {
			s.recordError(err)
			s.logf("iprange sync: pull failed: %v", err)
		}
		// jittered sleep until the next tick
		wait := s.interval() + jitter(SyncJitter)
		if wait < time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// PullOnce performs one fetch + apply.  Exported so the settings handler can
// drive a manual sync from the UI.
func (s *Sync) PullOnce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.hubURL(), nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	if s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Hub says nothing changed; no work to do, but the timestamp still
		// advances so the UI shows we checked.
		s.recordSuccess(0)
		return nil
	case http.StatusOK:
		// Fall through.
	default:
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB ceiling
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var doc AggregatedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schemaVersion=%d", doc.SchemaVersion)
	}
	if len(doc.Sources) == 0 {
		return fmt.Errorf("empty sources")
	}

	dir := s.dir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	written := 0
	for _, g := range BypassIPGroups {
		src, ok := doc.Sources[g.ID]
		if !ok {
			continue
		}
		if err := s.writeSource(dir, g.File, src); err != nil {
			s.logf("iprange sync: write %s: %v", g.ID, err)
			continue
		}
		written++
	}
	if written == 0 {
		return fmt.Errorf("no group matched hub doc")
	}

	// Capture Last-Modified for next request.
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		s.lastModified = lm
		s.saveLastModified()
	}

	Reload()
	s.recordSuccess(written)
	s.logf("iprange sync: wrote %d source(s) from hub", written)

	// Re-render http.inc / server.inc so the new prefixes land in the
	// `$is_bypass_ip` map.  nginx -s reload is the operator's call.  Render
	// failure is non-fatal: in-memory state is already updated, and the
	// operator can run `unmask render-nginx` to recover.
	if s.RenderFunc != nil {
		if err := s.RenderFunc(); err != nil {
			s.logf("iprange sync: render after pull failed: %v", err)
		}
	}
	return nil
}

// writeSource writes one vendor-shaped JSON atomically (= tmp + rename).
func (s *Sync) writeSource(dir, file string, src AggregatedSource) error {
	payload := iprangePayload{CreationTime: src.CreationTime}
	for _, p := range src.Prefixes {
		payload.Prefixes = append(payload.Prefixes, struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		}{IPv4Prefix: p.IPv4Prefix, IPv6Prefix: p.IPv6Prefix})
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.Base(file))
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// lastModifiedPath: the marker that lets PullOnce send a meaningful
// If-Modified-Since across restarts.
func (s *Sync) lastModifiedPath() string {
	return filepath.Join(s.dir(), ".last-modified")
}

func (s *Sync) loadLastModified() {
	b, err := os.ReadFile(s.lastModifiedPath())
	if err == nil {
		s.lastModified = string(b)
	}
}

func (s *Sync) saveLastModified() {
	_ = os.WriteFile(s.lastModifiedPath(), []byte(s.lastModified), 0o644)
}

// jitter returns a random duration in [-max, +max].  Uses crypto/rand so we
// don't need to seed math/rand (= which is forbidden via Date.now style
// reproducibility constraints for workflow scripts).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var n [8]byte
	if _, err := rand.Read(n[:]); err != nil {
		return 0
	}
	r := int64(binary.BigEndian.Uint64(n[:]) & 0x7FFFFFFFFFFFFFFF)
	return time.Duration(r%int64(2*max)) - max
}
