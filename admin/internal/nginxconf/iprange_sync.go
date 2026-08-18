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
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// snapshotMetaBase: written by iprange sync (hub pull, -file, and the
// release-time embed refresh alike) next to the per-vendor files; records
// when the address data was assembled.  The embed copy dates the binary's
// built-in snapshot, the override copy dates the last successful sync.
const snapshotMetaBase = "snapshot-meta.json"

type snapshotMeta struct {
	GeneratedAt string `json:"generatedAt"`
	// Signature: what the pull that wrote this snapshot established about
	// the document's authenticity -- "verified:<keyid>" or "unsigned".
	// Empty on snapshots written before this field existed.  Doctor reads
	// it: "the daemon verified a signature" is a fact about the PULL, so it
	// is recorded by the pull rather than re-derived later.
	Signature string `json:"signature,omitempty"`
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

	// InsecureTLS: skip transport certificate verification on the hub pull.
	// For hosts whose trust store cannot verify the hub (legacy CA bundles).
	// Honored ONLY together with signature verification: with this set, a
	// document that does not carry a valid detached signature is refused --
	// waiving the transport check while also accepting unsigned bytes would
	// hand the bypass list to whoever sits on the network path.
	InsecureTLS bool
	// RequireSignature: refuse an unsigned document even over verified TLS.
	// Implied by InsecureTLS; settable on its own for operators who want the
	// content check unconditionally.
	RequireSignature bool

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
	s.lastError = annotateSyncError(err.Error())
	s.stateMu.Unlock()
}

// annotateSyncError appends an operator hint to a TLS-trust failure.  On an EOL
// distro (CentOS 6/7) "x509: certificate signed by unknown authority" almost
// always means the host's CA bundle is too old to trust the feed's Let's Encrypt
// chain -- not an unmask bug.  unmask deliberately defers to the system trust
// store (a security tool must not override the operator's CA policy), so the fix
// is operator-side: refresh ca-certificates or add the ISRG roots, then restart.
// The bundled snapshot keeps protecting search bots meanwhile (= best-effort).
func annotateSyncError(msg string) string {
	m := strings.ToLower(msg)
	if strings.Contains(m, "x509:") ||
		strings.Contains(m, "failed to verify certificate") ||
		strings.Contains(m, "certificate signed by unknown authority") {
		return msg + "  (hint: the host CA bundle can't verify the feed's TLS certificate -- " +
			"common on EOL distros like CentOS 6/7. Refresh ca-certificates or add the ISRG roots, " +
			"then restart unmask; the bundled snapshot stays in effect meanwhile. See https://unmask.sh/docs/distros/.)"
	}
	return msg
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

func (s *Sync) signatureRequired() bool { return s.InsecureTLS || s.RequireSignature }

func (s *Sync) httpClient() *http.Client {
	if s.HTTPClient == nil && s.InsecureTLS {
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// The content signature carries the trust here (see the
				// InsecureTLS field comment); the transport check is what the
				// operator explicitly waived.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- operator opt-in escape hatch, gated on a mandatory content signature (signatureRequired)
			},
		}
	}
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

	sigState, err := s.verifyAgainstDetachedSig(ctx, body)
	if err != nil {
		return err
	}

	written, err := s.ingest(body, "hub", sigState)
	if err != nil {
		return err
	}

	// Capture Last-Modified for next request.
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		s.lastModified = lm
		s.saveLastModified()
	}

	s.recordSuccess(written)
	return nil
}

// verifyAgainstDetachedSig fetches <hub>.sig and checks it against body.
// A present-and-valid signature always passes; a present-and-INVALID one
// always fails (that is the tamper signal this exists for); an absent one
// fails only when the policy requires it, and is logged otherwise so an
// operator can see whether their hub signs at all.
func (s *Sync) verifyAgainstDetachedSig(ctx context.Context, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.hubURL()+FeedSigSuffix, nil)
	if err != nil {
		// A hub URL that cannot even form a .sig sibling (odd custom URLs)
		// counts as "no signature published there": fatal only when the
		// policy requires one.
		if s.signatureRequired() {
			return "", fmt.Errorf("feed signature required but its URL cannot be formed: %w", err)
		}
		s.logf("iprange sync: no signature URL (%v); proceeding on transport trust", err)
		return "unsigned", nil
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	resp, err := s.httpClient().Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	switch {
	case err == nil && resp.StatusCode == http.StatusOK:
		sig, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if rerr != nil {
			return "", fmt.Errorf("read signature: %w", rerr)
		}
		keyID, verr := VerifyFeedSignatureKeyID(body, sig)
		if verr != nil {
			return "", fmt.Errorf("feed signature: %w", verr)
		}
		return "verified:" + keyID, nil
	case s.signatureRequired():
		if err != nil {
			return "", fmt.Errorf("feed signature required but unavailable: %w", err)
		}
		return "", fmt.Errorf("feed signature required but the hub returned %d for it", resp.StatusCode)
	default:
		if err != nil {
			s.logf("iprange sync: no signature available (%v); proceeding on transport trust", err)
		} else {
			s.logf("iprange sync: hub serves no signature (%d); proceeding on transport trust", resp.StatusCode)
		}
		return "unsigned", nil
	}
}

// PullFromFile ingests an aggregated document from a local file instead of
// the hub.  For hosts whose trust store cannot verify the hub's certificate
// (the CentOS 6 class: no ISRG Root X1), where the operator transfers
// bypass-iprange-all.json out of band and points this at the copy -- without
// standing up a loopback HTTP server just to feed -url.
func (s *Sync) PullFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		s.recordError(err)
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 32<<20)) // same ceiling as the hub pull
	if err != nil {
		err = fmt.Errorf("read %s: %w", path, err)
		s.recordError(err)
		return err
	}
	// Sidecar signature: verify when present (a transferred file can be
	// checked exactly like a fetched one), require per policy.
	sigState := "unsigned"
	if sig, serr := os.ReadFile(path + FeedSigSuffix); serr == nil {
		keyID, verr := VerifyFeedSignatureKeyID(body, sig)
		if verr != nil {
			verr = fmt.Errorf("feed signature: %w", verr)
			s.recordError(verr)
			return verr
		}
		sigState = "verified:" + keyID
	} else if s.signatureRequired() {
		err := fmt.Errorf("feed signature required but %s%s is missing", path, FeedSigSuffix)
		s.recordError(err)
		return err
	}
	written, err := s.ingest(body, path, sigState)
	if err != nil {
		s.recordError(err)
		return err
	}
	s.recordSuccess(written)
	return nil
}

// ingest parses one aggregated document, writes the per-vendor files, and
// reloads + re-renders.  Shared by the hub pull and the local-file path so
// the two cannot drift; `from` names the origin in log lines only.
func (s *Sync) ingest(body []byte, from, sigState string) (int, error) {
	var doc AggregatedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0, fmt.Errorf("unmarshal: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return 0, fmt.Errorf("unsupported schemaVersion=%d", doc.SchemaVersion)
	}
	if len(doc.Sources) == 0 {
		return 0, fmt.Errorf("empty sources")
	}

	dir := s.dir()
	// Rollback guard: refuse a document older than the one already ingested.
	// With signatures on, an attacker's remaining move is replaying an OLD
	// signed document to reopen ranges a vendor has since rotated away from;
	// without them it still catches a misconfigured mirror serving stale
	// bytes.  Equal timestamps pass (idempotent re-pull).
	if newT, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
		if b, rerr := os.ReadFile(filepath.Join(dir, snapshotMetaBase)); rerr == nil {
			var m snapshotMeta
			if json.Unmarshal(b, &m) == nil {
				if curT, perr := time.Parse(time.RFC3339, m.GeneratedAt); perr == nil && newT.Before(curT) {
					return 0, fmt.Errorf("document generatedAt %s is older than the ingested %s (rollback refused)",
						doc.GeneratedAt, m.GeneratedAt)
				}
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", dir, err)
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
		return 0, fmt.Errorf("no group matched hub doc")
	}

	// Date the snapshot.  AutoBypassPresetIDs refuses to derive from data
	// older than its ceiling, and this file is what tells it (and doctor)
	// how old the data is.  The document's own generatedAt when it parses,
	// else the moment of this write.
	stamp := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
		stamp = t
	}
	if meta, err := json.Marshal(snapshotMeta{GeneratedAt: stamp.Format(time.RFC3339), Signature: sigState}); err == nil {
		if err := os.WriteFile(filepath.Join(dir, snapshotMetaBase), meta, 0o644); err != nil {
			s.logf("iprange sync: write %s: %v", snapshotMetaBase, err)
		}
	}

	Reload()
	s.logf("iprange sync: wrote %d source(s) from %s", written, from)

	// Re-render http.inc / server.inc so the new prefixes land in the
	// `$is_bypass_ip` map.  nginx -s reload is the operator's call.  Render
	// failure is non-fatal: in-memory state is already updated, and the
	// operator can run `unmask render-nginx` to recover.
	if s.RenderFunc != nil {
		if err := s.RenderFunc(); err != nil {
			s.logf("iprange sync: render after pull failed: %v", err)
		}
	}
	return written, nil
}

// writeSource writes one vendor-shaped JSON atomically (= tmp + rename).
func (s *Sync) writeSource(dir, file string, src AggregatedSource) error {
	// Local marshal type with omitempty so an ipv4 entry doesn't also carry an
	// empty "ipv6Prefix" (and vice versa) -- keeps the vendor-shaped, one-key-
	// per-entry format the embed snapshot + override files use, and roughly
	// halves the on-disk size.  iprangePayload (the load side) has no omitempty,
	// but omitempty only affects marshal, not unmarshal, so reads still work.
	type prefixEntry struct {
		IPv4Prefix string `json:"ipv4Prefix,omitempty"`
		IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	}
	payload := struct {
		CreationTime string        `json:"creationTime"`
		Prefixes     []prefixEntry `json:"prefixes"`
	}{CreationTime: src.CreationTime}
	for _, p := range src.Prefixes {
		// prefixEntry has the same fields as AggregatedPrefix; a conversion
		// avoids re-listing them (staticcheck S1016).
		payload.Prefixes = append(payload.Prefixes, prefixEntry(p))
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
