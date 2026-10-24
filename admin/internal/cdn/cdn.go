// Package cdn knows the addresses a content delivery network fetches from
// origins with -- the origin-facing side of Amazon CloudFront, Cloudflare and
// Fastly -- so that a request arriving from one of them is not mistaken for
// the client behind it.
//
// A CDN sits in front of a site and fetches what its visitors ask for from
// the origin, every visitor's request leaving from the same few addresses,
// and a scanner's with them: a probe for /wp-admin/ sent to a CDN hostname
// reaches the origin from a CloudFront address, trips the honeypot, and the
// ban lands on the address every page's images and scripts are fetched from.
// With the ban in force, the site loses its own CDN (an operator's report,
// 2026-10-24: 16 bans on 11 CloudFront addresses, 47 legitimate fetches a
// day behind them).  The address is shared by every customer of the CDN, so
// a ban on it is never on one client; this package is how the ban manager
// knows to leave it alone, how the doctor and the bans page say which bans
// sit on such an address, and how the trusted LB preset for CloudFront gets
// its ranges.
//
// The list comes from the unmask.sh hub (cdn-egress.json, signed and pulled
// like relay-egress.json) and, until a hub document is in, from the snapshot
// built into this binary.  An operator adds a CDN the list does not carry
// (an Akamai SiteShield map of their own) in settings > Network.  A leaf
// package: it parses, checks and holds the document; nginxconf fetches it
// and the ban manager, the render and the pages read it.
package cdn

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FileName: the hub document, and the copy kept in the sync dir.
const FileName = "cdn-egress.json"

// SchemaVersion: the document shape this build reads.
const SchemaVersion = 1

// MinRetention: a document keeping less than this share of the current one's
// prefixes is refused, as the hub refuses such a list.
const MinRetention = 0.5

// Custom: the vendor id of ranges the operator added in settings.
const Custom = "custom"

// Names: the CDNs this build can name in the UI, by id.  A document may
// carry others; they still apply, shown under their id.
var Names = map[string]string{
	"cloudfront": "Amazon CloudFront",
	"cloudflare": "Cloudflare",
	"fastly":     "Fastly",
	Custom:       "custom",
}

// Doc: the hub document.
type Doc struct {
	SchemaVersion int              `json:"schemaVersion"`
	GeneratedAt   string           `json:"generatedAt"`
	CDNs          map[string]Entry `json:"cdns"`
}

// Entry: one CDN's origin-facing ranges.
type Entry struct {
	Name   string   `json:"name"`
	Source string   `json:"source"`
	Ranges []string `json:"ranges"`
}

// Hit: what the table knows about an address.
type Hit struct {
	CDN string // vendor id, e.g. "cloudfront"
}

type span struct {
	p      netip.Prefix
	lo, hi netip.Addr
	hit    Hit
}

// Table: the compiled document -- non-overlapping address spans, sorted.
// Immutable once built.
type Table struct {
	spans       []span
	ranges      map[string][]string // vendor id -> its listed prefixes, as written
	GeneratedAt time.Time
	Prefixes    int
	Vendors     int
	// Snapshot: the table is the one built into the binary, not a hub
	// document (the settings page says so).
	Snapshot bool
}

// Compile builds the table.  Prefixes that do not parse are skipped -- one
// bad row must not cost the rest; overlaps keep the first span (the hub
// never emits them).
func Compile(doc Doc) (*Table, error) {
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported schemaVersion %d", doc.SchemaVersion)
	}
	t := &Table{ranges: map[string][]string{}}
	if doc.GeneratedAt != "" {
		if ts, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
			t.GeneratedAt = ts.UTC()
		}
	}
	ids := make([]string, 0, len(doc.CDNs))
	for id := range doc.CDNs {
		if validKey(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := doc.CDNs[id]
		for _, s := range e.Ranges {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				continue
			}
			p = p.Masked()
			if p.Addr().Is4In6() {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			t.spans = append(t.spans, span{p: p, lo: p.Addr(), hi: lastAddr(p), hit: Hit{CDN: id}})
			t.ranges[id] = append(t.ranges[id], p.String())
		}
		if len(t.ranges[id]) > 0 {
			t.Vendors++
		}
	}
	sort.Slice(t.spans, func(i, j int) bool {
		a, b := t.spans[i], t.spans[j]
		if a.lo.BitLen() != b.lo.BitLen() {
			return a.lo.BitLen() < b.lo.BitLen()
		}
		return a.lo.Less(b.lo)
	})
	// Overlaps: keep the first span, drop any that starts inside it.
	out := t.spans[:0]
	for _, s := range t.spans {
		if n := len(out); n > 0 && out[n-1].lo.BitLen() == s.lo.BitLen() && !out[n-1].hi.Less(s.lo) {
			continue
		}
		out = append(out, s)
	}
	t.spans = out
	t.Prefixes = len(out)
	return t, nil
}

// validKey: a vendor id that can travel into a log line, a settings value
// and a config comment: letters, digits, ".", "_", "-".
func validKey(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	b := a.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}

// Lookup reports the CDN span an address falls in.  Nil-safe.
func (t *Table) Lookup(a netip.Addr) (Hit, bool) {
	if t == nil || !a.IsValid() {
		return Hit{}, false
	}
	a = a.Unmap()
	i := sort.Search(len(t.spans), func(i int) bool {
		s := t.spans[i]
		if s.lo.BitLen() != a.BitLen() {
			return s.lo.BitLen() > a.BitLen()
		}
		return a.Less(s.lo)
	})
	if i == 0 {
		return Hit{}, false
	}
	s := t.spans[i-1]
	if s.lo.BitLen() != a.BitLen() || s.hi.Less(a) {
		return Hit{}, false
	}
	return s.hit, true
}

// Ranges: the listed prefixes of one vendor, in address order; nil when the
// table does not carry it.  The CloudFront trusted-LB preset reads its
// ranges here.
func (t *Table) Ranges(id string) []string {
	if t == nil {
		return nil
	}
	return t.ranges[id]
}

// VendorIDs: the vendors the table carries, sorted.
func (t *Table) VendorIDs() []string {
	if t == nil {
		return nil
	}
	ids := make([]string, 0, len(t.ranges))
	for id := range t.ranges {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Each calls fn for every listed prefix in address order.
func (t *Table) Each(fn func(p netip.Prefix, h Hit)) {
	if t == nil {
		return
	}
	for _, s := range t.spans {
		fn(s.p, s.hit)
	}
}

var current atomic.Pointer[Table]

// Current: the hub document loaded, nil when none is.
func Current() *Table { return current.Load() }

// Set installs t (nil clears).  For the sync, the loader and tests.
func Set(t *Table) { current.Store(t) }

//go:embed snapshot.json
var snapshotJSON []byte

var (
	snapshotOnce sync.Once
	snapshot     *Table
)

// Snapshot: the list built into this binary -- the vendors' published
// origin-facing ranges as of the build -- for an install that has no hub
// document yet.
func Snapshot() *Table {
	snapshotOnce.Do(func() {
		t, err := Parse(snapshotJSON)
		if err != nil {
			panic("cdn: built-in snapshot: " + err.Error())
		}
		t.Snapshot = true
		snapshot = t
	})
	return snapshot
}

// Active: the table in use -- the hub document when one is loaded, else
// the built-in snapshot.
func Active() *Table {
	if t := current.Load(); t != nil {
		return t
	}
	return Snapshot()
}

// ParsePrefixes: the operator's own ranges from settings, those that parse.
func ParsePrefixes(strs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			if a, aerr := netip.ParseAddr(strings.TrimSpace(s)); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		out = append(out, p.Masked())
	}
	return out
}

// Match reports which CDN an address belongs to: a vendor of the active
// table, or Custom for one of the operator's own ranges.  "" and false for
// an address that is nobody's egress, or does not parse.
func Match(ip string, extra []netip.Prefix) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if h, ok := Active().Lookup(a); ok {
		return h.CDN, true
	}
	for _, p := range extra {
		if p.Contains(a) {
			return Custom, true
		}
	}
	return "", false
}

// Parse decodes and compiles a document.
func Parse(body []byte) (*Table, error) {
	var doc Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return Compile(doc)
}

// LoadDir installs the copy kept in dir, if there is one.  A missing file is
// not an error: the built-in snapshot stands in.
func LoadDir(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	t, err := Parse(b)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dir, FileName), err)
	}
	Set(t)
	return nil
}

// Ingest checks a pulled document against the one in use and, when it passes,
// writes it to dir and installs it.  Refused: a document that does not parse,
// one older than the table in use (a replayed signed document; the built-in
// snapshot counts, so a hub document older than this build is refused too),
// and one with less than MinRetention of its prefixes.
func Ingest(dir string, body []byte) (*Table, error) {
	t, err := Parse(body)
	if err != nil {
		return nil, err
	}
	if cur := Active(); cur != nil {
		if !t.GeneratedAt.IsZero() && !cur.GeneratedAt.IsZero() && t.GeneratedAt.Before(cur.GeneratedAt) {
			return nil, fmt.Errorf("document generatedAt %s is older than the one in use (%s): rollback refused",
				t.GeneratedAt.Format(time.RFC3339), cur.GeneratedAt.Format(time.RFC3339))
		}
		if float64(t.Prefixes) < MinRetention*float64(cur.Prefixes) {
			return nil, fmt.Errorf("prefix count dropped %d -> %d: keeping the list in use", cur.Prefixes, t.Prefixes)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	Set(t)
	return t, nil
}

// Name is the CDN's display name.
func Name(id string) string {
	if n, ok := Names[id]; ok {
		return n
	}
	return id
}
