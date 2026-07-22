// Package browsermajors keeps the stale-browser tier's current-stable
// baselines fresh by subscribing to the unmask.sh hub aggregate.
//
// The hub fetches the vendor version feeds (Chrome versionhistory, Mozilla
// product-details) once per day and republishes one small JSON.  Each install
// polls that single URL — not the vendors — so the vendors see one fetch/day
// total and every install keeps working when a vendor endpoint changes shape
// (the hub absorbs the breakage).
//
// The fetched values feed settings.SetHubBrowserBaselines; the resolve chain
// (GlobalConfig.Current*MajorResolved) prefers an operator-set value, then the
// NEWER of hub vs the shipped built-in — so a hub outage, a stale disk state,
// or a hub rollback can never drag a baseline below what this binary shipped
// with.  The last good document is persisted under /var/lib/unmask so a
// restart (and the render-nginx CLI) starts from it without waiting for the
// next pull.
package browsermajors

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

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// DefaultHubURL: the hub-aggregated document (rides the same nginx-served
// feed dir as the bypass-IP aggregate).
const DefaultHubURL = "https://unmask.sh/dl/feed/iprange/browser-majors.json"

// DefaultStatePath: where the last good document is persisted.
const DefaultStatePath = "/var/lib/unmask/browser-majors.json"

// DefaultInterval / Jitter / InitialDelay mirror the bypass-IP sync's pacing:
// daily ± jitter spreads installs across the day; the initial delay lets
// cmdServe finish its startup render first (and trails the iprange sync's
// 30s so the two pulls don't fire in the same instant).
const (
	DefaultInterval = 24 * time.Hour
	Jitter          = 2 * time.Hour
	InitialDelay    = 60 * time.Second
)

// Family / Doc mirror the hub's published shape (kept in sync with the site
// repo by schemaVersion; no cross-repo import).
type Family struct {
	Major     int    `json:"major"`
	Version   string `json:"version,omitempty"`
	ESRMajors []int  `json:"esrMajors,omitempty"`
}

// Doc: the hub document.
type Doc struct {
	SchemaVersion int    `json:"schemaVersion"`
	GeneratedAt   string `json:"generatedAt"`
	Chrome        Family `json:"chrome"`
	Firefox       Family `json:"firefox"`
}

// maxAdvance caps how far above the shipped built-ins a hub value may sit.
// ~200 majors ≈ 15 years of releases: anything beyond that is a corrupted or
// hostile document, and accepting it would raise the stale threshold to
// "everything" (current-lag catches every real browser).
const maxAdvance = 200

// Validate rejects a document the resolve chain must never see: wrong schema,
// absurd majors (below the shipped floor - anything, or wildly above it).
// A major merely OLDER than the built-in is not an error — the resolve
// chain's max() simply ignores it (hub lagging a fresh binary is normal).
func Validate(doc Doc) error {
	if doc.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schemaVersion %d", doc.SchemaVersion)
	}
	if doc.Chrome.Major <= 0 && doc.Firefox.Major <= 0 {
		return fmt.Errorf("no majors in document")
	}
	if doc.Chrome.Major > settings.DefaultCurrentChromeMajor+maxAdvance {
		return fmt.Errorf("chrome major %d implausibly far above the built-in %d",
			doc.Chrome.Major, settings.DefaultCurrentChromeMajor)
	}
	if doc.Firefox.Major > settings.DefaultCurrentFirefoxMajor+maxAdvance {
		return fmt.Errorf("firefox major %d implausibly far above the built-in %d",
			doc.Firefox.Major, settings.DefaultCurrentFirefoxMajor)
	}
	for _, m := range doc.Firefox.ESRMajors {
		if m < 0 || m > settings.DefaultCurrentFirefoxMajor+maxAdvance {
			return fmt.Errorf("implausible esr major %d", m)
		}
	}
	return nil
}

// Apply publishes a validated document to the settings resolve chain.
func Apply(doc Doc, fetchedAt time.Time) {
	settings.SetHubBrowserBaselines(settings.HubBrowserBaselinesData{
		Chrome:     doc.Chrome.Major,
		Firefox:    doc.Firefox.Major,
		FirefoxESR: doc.Firefox.ESRMajors,
		FetchedAt:  fetchedAt,
	})
}

// LoadState reads + validates + applies the persisted document at path.
// Silently no-ops when the file is absent (fresh install / never synced);
// returns an error only for a present-but-broken file.  Used by serve startup
// AND the render-nginx CLI so a one-shot render sees the same baselines the
// daemon runs with.
func LoadState(path string) error {
	if path == "" {
		path = DefaultStatePath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc Doc
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if err := Validate(doc); err != nil {
		return fmt.Errorf("validate %s: %w", path, err)
	}
	at := time.Time{}
	if st, err := os.Stat(path); err == nil {
		at = st.ModTime()
	}
	Apply(doc, at)
	return nil
}

// Sync polls the hub on an interval and applies + persists refreshed
// baselines.  Construct via NewSync, then Start(ctx) in a goroutine.
type Sync struct {
	HubURL     string        // empty → DefaultHubURL
	StatePath  string        // empty → DefaultStatePath
	Interval   time.Duration // 0 → DefaultInterval
	HTTPClient *http.Client  // nil → 30s timeout
	UserAgent  string
	Logger     *log.Logger // nil → log default

	stateMu      sync.Mutex
	lastSyncedAt time.Time
	lastError    string
}

// NewSync returns a Sync with defaults filled in.
func NewSync() *Sync { return &Sync{} }

// LastSyncedAt returns the time of the last successful pull; zero when none.
func (s *Sync) LastSyncedAt() time.Time {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastSyncedAt
}

// LastError returns the most recent pull's error message ("" on success /
// never pulled).
func (s *Sync) LastError() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastError
}

func (s *Sync) hubURL() string {
	if s.HubURL != "" {
		return s.HubURL
	}
	return DefaultHubURL
}

func (s *Sync) statePath() string {
	if s.StatePath != "" {
		return s.StatePath
	}
	return DefaultStatePath
}

func (s *Sync) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultInterval
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

// Start loads the persisted state, then polls until ctx is cancelled.
func (s *Sync) Start(ctx context.Context) {
	if err := LoadState(s.statePath()); err != nil {
		s.logf("browsermajors: state load: %v", err)
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(InitialDelay):
	}
	for {
		if err := s.PullOnce(ctx); err != nil {
			s.logf("browsermajors sync: pull failed: %v", err)
		}
		wait := s.interval() + jitter(Jitter)
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

// PullOnce performs one fetch + validate + apply + persist, recording its
// outcome for the UI.  Exported so the settings UI can drive a manual sync.
func (s *Sync) PullOnce(ctx context.Context) (err error) {
	defer func() {
		s.stateMu.Lock()
		if err != nil {
			s.lastError = err.Error()
		} else {
			s.lastSyncedAt = time.Now().UTC()
			s.lastError = ""
		}
		s.stateMu.Unlock()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.hubURL(), nil)
	if err != nil {
		return err
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB ceiling
	if err != nil {
		return err
	}
	var doc Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if err := Validate(doc); err != nil {
		return err
	}
	Apply(doc, time.Now().UTC())
	if err := s.persist(body); err != nil {
		// Non-fatal: the in-memory baselines are applied; only restart
		// continuity suffers.
		s.logf("browsermajors: persist: %v", err)
	}
	s.logf("browsermajors sync: chrome=%d firefox=%d esr=%v",
		doc.Chrome.Major, doc.Firefox.Major, doc.Firefox.ESRMajors)
	return nil
}

func (s *Sync) persist(body []byte) error {
	path := s.statePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// jitter returns a crypto-random duration in [-max, +max] (same shape as the
// bypass-IP sync's; math/rand is avoided to keep the linter profile uniform).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0
	}
	n := int64(binary.LittleEndian.Uint64(buf[:]) % uint64(2*max))
	return time.Duration(n) - max
}
