// install.go — fetch the DB-IP Lite mmdb (country / ASN) and atomically install it.
//
// DB-IP Lite is CC BY 4.0 (= redistribution allowed with attribution).
// We do NOT bundle the file in the rpm/deb; instead, this helper downloads it
// on demand, trying two sources in order:
//
//  1. the unmask.sh mirror (stable URL, refreshed monthly server-side):
//     https://unmask.sh/dl/ipgeo/dbip-country-lite.mmdb.gz
//  2. db-ip.com's month-stamped snapshot (current month, then previous):
//     https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
//
// The mirror is tried first because db-ip.com's path 404s for a few days at each
// month boundary; if the mirror is unreachable we fall through to db-ip.com.
// A caller-supplied URLTemplate opts out of the mirror and uses only db-ip.com.
//
// Used by both the `unmask install-ipgeo` CLI and the web UI's 1-click
// install button.
package ipgeo

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// DefaultMMDBPath: standard install location for the country DB.  Matches
// the `ipgeo.mmdb_path` default in settings.defaults().  Owned by the unmask
// user (= service account); mode 0640 so other tools can't accidentally
// read it.
const DefaultMMDBPath = "/var/lib/unmask/ipgeo/dbip-country.mmdb"

// DefaultASNPath: standard install location for the ASN DB.  Optional add-on
// that powers the dashboard's ASN column / popover.
const DefaultASNPath = "/var/lib/unmask/ipgeo/dbip-asn.mmdb"

// InstallKind: which DB-IP Lite snapshot to fetch.  "" defaults to Country.
type InstallKind string

const (
	InstallKindCountry InstallKind = "country"
	InstallKindASN     InstallKind = "asn"
)

// DefaultPathForKind returns the canonical install path for kind.  Used by
// the CLI / web handler when the caller does not pre-supply a path.
func DefaultPathForKind(k InstallKind) string {
	if k == InstallKindASN {
		return DefaultASNPath
	}
	return DefaultMMDBPath
}

// InstallResult describes a completed install for caller reporting.
type InstallResult struct {
	Path     string // final on-disk path
	Source   string // source URL actually fetched
	Bytes    int64  // bytes written (uncompressed)
	Month    string // YYYY-MM of the snapshot that succeeded
	Fallback bool   // true if we had to fall back to the previous month
}

// InstallOptions controls the installer behavior.  Zero values pick sane
// defaults (country DB, current month, default URL, default path).
type InstallOptions struct {
	// Kind: which DB-IP Lite snapshot to fetch.  Empty -> Country.
	Kind InstallKind
	// Path: where to write the final mmdb.  Empty -> DefaultPathForKind(Kind).
	Path string
	// URLTemplate: printf-style template that takes one %s argument (YYYY-MM).
	// Empty -> the official DB-IP Lite URL for the chosen Kind.  Override
	// for testing.
	URLTemplate string
	// HTTPClient: caller can pass a pre-configured client (= timeouts, proxy
	// settings).  Nil -> a fresh client with 60s timeout.
	HTTPClient *http.Client
	// Now: time anchor for month detection.  Zero -> time.Now().UTC().
	// Pass a fixed time in tests for determinism.
	Now time.Time
	// MaxBytes: hard cap on the uncompressed payload (= protect against a
	// hostile / corrupt server).  Zero -> 50 MiB (= comfortably above the
	// ~3 MiB country-lite / ~6 MiB asn-lite payload).
	MaxBytes int64
}

const (
	defaultCountryURLTemplate = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"
	defaultASNURLTemplate     = "https://download.db-ip.com/free/dbip-asn-lite-%s.mmdb.gz"
	defaultMaxBytes           = 50 * 1024 * 1024

	// unmask re-hosts the unmodified DB-IP Lite snapshot (CC BY 4.0) at a stable
	// URL, refreshed monthly by tools/unmask-dbip-mirror.sh.  We try it first so
	// installs don't depend on db-ip.com's month-stamped path (which 404s for a
	// few days at each month boundary) -- with a transparent fall-back to
	// db-ip.com if the mirror is unreachable.
	mirrorCountryURL = "https://unmask.sh/dl/ipgeo/dbip-country-lite.mmdb.gz"
	mirrorASNURL     = "https://unmask.sh/dl/ipgeo/dbip-asn-lite.mmdb.gz"
)

// mirrorURLForKind returns the unmask.sh mirror URL for kind.
func mirrorURLForKind(k InstallKind) string {
	if k == InstallKindASN {
		return mirrorASNURL
	}
	return mirrorCountryURL
}

// defaultURLTemplateForKind picks the canonical DB-IP Lite URL for kind.
func defaultURLTemplateForKind(k InstallKind) string {
	if k == InstallKindASN {
		return defaultASNURLTemplate
	}
	return defaultCountryURLTemplate
}

// InstallDBIPLite downloads + verifies + atomic-renames the latest DB-IP
// Country Lite mmdb into opts.Path.  Returns an InstallResult describing
// the outcome, or an error if no month-snapshot could be fetched.
//
// Verification steps (= each on the temporary `.next` file before atomic mv):
//  1. Content-Length and stream length agree
//  2. maxminddb.Open succeeds (= valid mmdb structure)
//  3. A lookup on a known public IP returns a country (= sanity smoke test)
func InstallDBIPLite(opts InstallOptions) (*InstallResult, error) {
	kind := opts.Kind
	if kind == "" {
		kind = InstallKindCountry
	}
	path := opts.Path
	if path == "" {
		path = DefaultPathForKind(kind)
	}
	tmpl := opts.URLTemplate
	if tmpl == "" {
		tmpl = defaultURLTemplateForKind(kind)
	}
	// The mmdb is fetched without a checksum/signature, so TLS is the only
	// integrity guarantee -- refuse a plain-http override that a MITM could
	// swap for a malicious (but structurally valid) geo DB driving verdicts.
	if !strings.HasPrefix(tmpl, "https://") {
		return nil, fmt.Errorf("ipgeo URL must be https:// (got %q)", tmpl)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	// Source order: the unmask mirror first (stable URL, refreshed monthly
	// server-side), then db-ip.com's current + previous month (snapshots can
	// publish several days into the month, so a first-of-month run would
	// otherwise fail predictably).  A caller-supplied URLTemplate opts out of
	// the mirror and uses only db-ip.com.
	months := []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")}
	type source struct {
		url   string
		month string
		soft  bool // soft = fall through to the next source on ANY error
	}
	var sources []source
	if opts.URLTemplate == "" {
		sources = append(sources, source{url: mirrorURLForKind(kind), soft: true})
	}
	for _, month := range months {
		sources = append(sources, source{url: fmt.Sprintf(tmpl, month), month: month})
	}
	var lastErr error
	for i, src := range sources {
		written, err := downloadOne(src.url, path, maxBytes, client)
		if err == nil {
			return &InstallResult{
				Path:     path,
				Source:   src.url,
				Bytes:    written,
				Month:    src.month,
				Fallback: i > 0,
			}, nil
		}
		lastErr = err
		// A mirror failure (soft) or a "not yet published" 404 falls through to
		// the next source; a hard error from a db-ip.com URL is returned.
		if src.soft || errors.Is(err, errNotPublished) {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("dbip-lite: no source succeeded out of %d (%w)", len(sources), lastErr)
}

// AutoFetchMissing fetches the managed DB-IP Lite mmdb(s) in the background when
// they are configured at their default path but not yet on disk -- the daemon's
// first-run path, so geo features come up without a manual `unmask install-ipgeo`
// or 1-click, regardless of how unmask was installed (binary / docker / any
// distro).  Non-blocking: spawns a goroutine and returns immediately.  Fetches
// are bounded-retry (covers a host briefly offline at boot) and non-fatal.  Only
// default managed paths are touched; a custom mmdb_path is the operator's own
// file and is left alone.  gip is reloaded so the geo axis sees the new file
// without a restart.
func AutoFetchMissing(countryPath, asnPath string, gip *Reader) {
	type job struct {
		kind InstallKind
		path string
	}
	var jobs []job
	if countryPath == DefaultMMDBPath && !fileExists(countryPath) {
		jobs = append(jobs, job{InstallKindCountry, countryPath})
	}
	if asnPath == DefaultASNPath && !fileExists(asnPath) {
		jobs = append(jobs, job{InstallKindASN, asnPath})
	}
	if len(jobs) == 0 {
		return
	}
	go func() {
		// Pass 0 fires immediately; later passes retry only what's still missing
		// after a backoff (covers "network not up yet at boot").
		backoffs := []time.Duration{0, 60 * time.Second, 5 * time.Minute}
		remaining := jobs
		for _, wait := range backoffs {
			if wait > 0 {
				time.Sleep(wait)
			}
			var failed []job
			for _, j := range remaining {
				res, err := InstallDBIPLite(InstallOptions{Kind: j.kind, Path: j.path})
				if err != nil {
					log.Printf("ipgeo: first-run auto-fetch of %s failed: %v", j.kind, err)
					failed = append(failed, j)
					continue
				}
				log.Printf("ipgeo: auto-fetched %s on first run from %s (%d bytes)", j.kind, res.Source, res.Bytes)
			}
			remaining = failed
			if len(remaining) == 0 {
				break
			}
		}
		// Reload if at least one fetch landed so /api/check picks it up without a
		// restart (clear-then-reload forces past the unchanged-path short-circuit).
		if len(remaining) < len(jobs) && gip != nil {
			gip.Reload("", "")
			gip.Reload(countryPath, asnPath)
			log.Printf("ipgeo: reloaded reader after first-run auto-fetch")
		}
		if len(remaining) > 0 {
			log.Printf("ipgeo: first-run auto-fetch gave up on %d db(s) (offline?); run `unmask install-ipgeo` later", len(remaining))
		}
	}()
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

var errNotPublished = errors.New("db-ip snapshot not yet published")

// downloadOne fetches a single URL into `path` via tmp file + atomic mv.
// Returns the byte count on success or errNotPublished on 404.
func downloadOne(url, path string, maxBytes int64, client *http.Client) (int64, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("User-Agent", "unmask/install-mmdb (+https://unmask.sh)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("%s: %w", url, errNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("gunzip header: %w", err)
	}
	defer gz.Close()

	// CreateTemp (random name + O_EXCL) so a pre-planted "<path>.next" symlink
	// can't redirect this (possibly root-run) write to an attacker-chosen target.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".next-*")
	if err != nil {
		return 0, fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	_ = os.Chmod(tmp, 0o640) // CreateTemp makes 0600; restore the intended 0640
	written, copyErr := io.Copy(f, &io.LimitedReader{R: gz, N: maxBytes + 1})
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("write %s: %w", tmp, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("close %s: %w", tmp, closeErr)
	}
	if written > maxBytes {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("%s: payload exceeded %d bytes (= corrupt or hostile server)", url, maxBytes)
	}

	if err := verifyMMDB(tmp); err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("verify %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return written, nil
}

// MMDBInfo: metadata about a candidate mmdb file (= for the UI badge that
// distinguishes MaxMind vs DB-IP vs IP2Location etc.).  All fields are
// best-effort; on file / parse error the zero value is returned with a
// non-nil error so the UI can show "(unknown)" without crashing.
type MMDBInfo struct {
	Path         string    // absolute path
	Exists       bool      // false = file not present
	Size         int64     // bytes
	DatabaseType string    // e.g. "GeoLite2-Country", "DBIP-Country-Lite"
	Vendor       string    // human label derived from DatabaseType: "MaxMind", "DB-IP", "IP2Location", "Unknown"
	BuildTime    time.Time // from mmdb metadata BuildEpoch
	IPVersion    uint      // 4 (= v4 only) or 6 (= v4+v6)
}

// InspectMMDB reads Metadata from a candidate file.  Pure function: opens
// read-only, never modifies.  Returns (info, nil) on success; on any error
// returns (info-with-Exists-flag-set-correctly, err) so callers can decide
// whether to show the row dimmed / hidden.
func InspectMMDB(path string) (MMDBInfo, error) {
	info := MMDBInfo{Path: path}
	st, err := os.Stat(path)
	if err != nil {
		return info, err
	}
	info.Exists = true
	info.Size = st.Size()
	db, err := maxminddb.Open(path)
	if err != nil {
		return info, fmt.Errorf("open mmdb: %w", err)
	}
	defer db.Close()
	meta := db.Metadata
	info.DatabaseType = meta.DatabaseType
	info.IPVersion = meta.IPVersion
	if meta.BuildEpoch > 0 {
		info.BuildTime = time.Unix(int64(meta.BuildEpoch), 0).UTC()
	}
	info.Vendor = vendorFromDatabaseType(meta.DatabaseType)
	return info, nil
}

// vendorFromDatabaseType maps the embedded DatabaseType string into a
// human-readable vendor label.  Patterns observed in the wild:
//
//	"GeoLite2-*" / "GeoIP2-*"           -> MaxMind (free + commercial)
//	"DBIP-*-Lite" / "DBIP-*"            -> DB-IP (free + commercial)
//	"IP2Location-DBxxx"                  -> IP2Location
func vendorFromDatabaseType(t string) string {
	switch {
	case strings.HasPrefix(t, "GeoLite2") || strings.HasPrefix(t, "GeoIP2"):
		return "MaxMind"
	case strings.HasPrefix(t, "DBIP"):
		return "DB-IP"
	case strings.HasPrefix(t, "IP2Location"):
		return "IP2Location"
	case t == "":
		return ""
	default:
		return "Unknown"
	}
}

// GeoCIDRsForCountries walks every network entry in the mmdb at path and
// returns the IPv4 / IPv6 CIDRs that resolve to one of the requested ISO
// country codes.  Used by the native-mode nginx renderer to materialize a
// `geo` block listing only the countries the operator has rules for (= the
// long tail falls through to the default).
//
// `codes` is matched case-insensitively but the ISO codes returned by all
// upstream mmdb vendors (= MaxMind / DB-IP / IP2Location) are uppercase.
//
// Returns (lines, error) where each line is "<cidr> <ISO>;\n", suitable
// for embedding inside a `geo {}` directive.  Caller is expected to write
// the surrounding `geo $binary_remote_addr $var { default ""; ... }`.
//
// On any I/O / parse error, returns the lines accumulated so far and the
// first error.  The mmdb is opened read-only and closed before return.
func GeoCIDRsForCountries(path string, codes []string) (string, error) {
	if path == "" || len(codes) == 0 {
		return "", nil
	}
	wanted := make(map[string]bool, len(codes))
	for _, c := range codes {
		wanted[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer db.Close()

	var b strings.Builder
	// Reuse the same struct across iterations so we don't keep allocating.
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	nets := db.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		cidr, err := nets.Network(&rec)
		if err != nil {
			continue
		}
		if rec.Country.ISOCode == "" {
			continue
		}
		if !wanted[rec.Country.ISOCode] {
			continue
		}
		b.WriteString("    ")
		b.WriteString(cidr.String())
		b.WriteString(" ")
		b.WriteString(rec.Country.ISOCode)
		b.WriteString(";\n")
	}
	if err := nets.Err(); err != nil {
		return b.String(), err
	}
	return b.String(), nil
}

// verifyMMDB opens the downloaded file with the same library admin uses and
// runs a known-IP lookup.  Catches truncated / corrupt downloads and
// servers returning HTML pages with .mmdb.gz Content-Type.
func verifyMMDB(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("not a valid mmdb: %w", err)
	}
	defer db.Close()

	// Sanity lookup against Google DNS (= almost certainly in any IP-geo DB
	// that covers US).  Empty result is acceptable (= a future DB-IP Lite
	// trim could drop coverage); we only fail on parse errors.
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := db.Lookup(net.ParseIP("8.8.8.8"), &rec); err != nil {
		return fmt.Errorf("sample lookup failed: %w", err)
	}
	return nil
}
