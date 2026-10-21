// Package relay knows the addresses that shared-egress relays -- Apple's
// iCloud Private Relay, the cloud proxies of Zscaler, Netskope, Cato Networks
// and Cisco Umbrella -- send their users' traffic from, and, for a relay that
// says so, the country those addresses serve.
//
// Country databases place many relay addresses in the wrong country: one
// address carries a whole region's users and the relay moves its addresses
// between regions faster than a database follows.  A Japanese iPhone behind
// the relay then counts, and is judged, as Brunei or Guam.  The relay's own
// list says where its users are, so the lookups that place a visitor (the
// statistics, bot hunt, the IP popover, the native country rule) take the
// relay's word for those addresses, and the network rules leave them alone:
// a relay address is shared by many people, not run by the network it sits
// in.
//
// A cloud proxy such as Zscaler is the other shape: its addresses sit where
// the databases say they do, but one user's requests leave from several of
// them, and a pass cookie bound to one address dropped off between a page and
// the form posted from it.  Such a relay lists its ranges with no country and
// asks to be bound as a whole: the cookie then follows the user across the
// proxy's addresses, and nothing else about the lookups changes.
//
// The list comes from the unmask.sh hub (relay-egress.json, signed like the
// bypass-IP aggregate, pulled by the same sync), which builds it once a day
// from the relay's published list.  This package is a leaf -- it parses,
// checks and holds the document; nginxconf fetches it and ipgeo / the render
// read it -- so both sides can use it without importing each other.
package relay

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// FileName: the hub document, and the copy kept in the sync dir.
const FileName = "relay-egress.json"

// SchemaVersion: the document shape this build reads.
const SchemaVersion = 1

// MinRetention: a document keeping less than this share of the current one's
// prefixes is refused, as the hub refuses such a list.
const MinRetention = 0.5

// Names: the relays this build can name in the UI, by id.  A document may
// carry others; they still apply, shown under their id.
var Names = map[string]string{
	"apple-private-relay": "iCloud Private Relay",
	"zscaler":             "Zscaler",
	"netskope":            "Netskope",
	"cato-networks":       "Cato Networks",
	"cisco-umbrella":      "Cisco Umbrella",
}

// BindRelay: the Entry.Bind value of a relay bound as a whole.
const BindRelay = "relay"

// Doc: the hub document.
type Doc struct {
	SchemaVersion int              `json:"schemaVersion"`
	GeneratedAt   string           `json:"generatedAt"`
	Relays        map[string]Entry `json:"relays"`
}

// Entry: one relay's egress.  Countries holds the ranges the relay places in
// a country (the lookups take that country over the database's); Ranges the
// ones it does not place -- a proxy whose addresses sit where the database
// says, listed only so a pass cookie can follow its users between them.  Bind
// says what a cookie issued inside one of its ranges is bound to: the listed
// range (empty), or the relay as a whole (BindRelay) for a proxy that sends
// one visitor's requests from several of its ranges.
type Entry struct {
	Name      string              `json:"name"`
	Source    string              `json:"source"`
	Countries map[string][]string `json:"countries"`
	Ranges    []string            `json:"ranges,omitempty"`
	Bind      string              `json:"bind,omitempty"`
}

// Hit: what the table knows about an address.
type Hit struct {
	Relay   string // relay id, e.g. "apple-private-relay"
	Country string // ISO 3166-1 alpha-2 the relay gives the address; "" when it gives none
	// Key: what a pass cookie from the range is bound to when that is not
	// the range itself -- the relay's id, for a relay bound as a whole.
	Key string
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
	GeneratedAt time.Time
	Prefixes    int
	Countries   int
}

// Compile builds the table.  Prefixes that do not parse, and country codes
// that are not two letters, are skipped -- one bad row must not cost the
// rest; overlaps keep the first span (the hub never emits them).  A relay
// bound as a whole gets its id as the key, if the id can travel as an nginx
// geo value and a header (letters, digits, ".", "_", "-"); otherwise its
// ranges are bound one by one like any other.
func Compile(doc Doc) (*Table, error) {
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported schemaVersion %d", doc.SchemaVersion)
	}
	t := &Table{}
	if g, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
		t.GeneratedAt = g
	}
	seen := map[string]bool{}
	for id, e := range doc.Relays {
		key := ""
		if e.Bind == BindRelay && validKey(id) {
			key = id
		}
		add := func(raw, cc string) {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return
			}
			p = p.Masked()
			t.spans = append(t.spans, span{p: p, lo: p.Addr(), hi: lastAddr(p), hit: Hit{Relay: id, Country: cc, Key: key}})
			t.Prefixes++
			if cc != "" {
				seen[cc] = true
			}
		}
		for cc, ps := range e.Countries {
			cc = strings.ToUpper(strings.TrimSpace(cc))
			if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
				continue
			}
			for _, raw := range ps {
				add(raw, cc)
			}
		}
		for _, raw := range e.Ranges {
			add(raw, "")
		}
	}
	t.Countries = len(seen)
	sort.Slice(t.spans, func(i, j int) bool { return t.spans[i].lo.Less(t.spans[j].lo) })
	// Drop a span that starts inside the one kept before it.
	kept := t.spans[:0]
	for _, s := range t.spans {
		if n := len(kept); n > 0 && kept[n-1].lo.BitLen() == s.lo.BitLen() && !kept[n-1].hi.Less(s.lo) {
			continue
		}
		kept = append(kept, s)
	}
	t.spans = kept
	if len(t.spans) == 0 {
		return nil, fmt.Errorf("no usable prefixes")
	}
	return t, nil
}

// validKey reports whether id can stand as a bind key: 1-64 of the
// characters that pass through an nginx geo value and an HTTP header verbatim.
func validKey(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8
		switch {
		case lo >= bits:
			b[i] = 0xff
		case lo+8 > bits:
			b[i] |= 0xff >> uint(bits-lo)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Lookup reports the relay span an address falls in.  Nil-safe.
func (t *Table) Lookup(a netip.Addr) (Hit, bool) {
	_, h, ok := t.LookupPrefix(a)
	return h, ok
}

// LookupPrefix is Lookup with the listed prefix the address falls in.
func (t *Table) LookupPrefix(a netip.Addr) (netip.Prefix, Hit, bool) {
	if t == nil || !a.IsValid() {
		return netip.Prefix{}, Hit{}, false
	}
	a = a.Unmap()
	i := sort.Search(len(t.spans), func(i int) bool { return a.Less(t.spans[i].lo) })
	if i == 0 {
		return netip.Prefix{}, Hit{}, false
	}
	s := t.spans[i-1]
	if s.lo.BitLen() != a.BitLen() || s.hi.Less(a) {
		return netip.Prefix{}, Hit{}, false
	}
	return s.p, s.hit, true
}

// Each calls fn for every listed prefix in address order (the render walks
// them).
func (t *Table) Each(fn func(p netip.Prefix, h Hit)) {
	if t == nil {
		return
	}
	for _, s := range t.spans {
		fn(s.p, s.hit)
	}
}

var (
	current atomic.Pointer[Table]
	off     atomic.Pointer[func() bool]
)

// Current: the table loaded, nil when none is -- whether or not it is in use
// (the settings page reports it either way).
func Current() *Table { return current.Load() }

// Active: the table the lookups and the render use -- nil when none is
// loaded or the operator's switch (SetOff) says the list is off.
func Active() *Table {
	if f := off.Load(); f != nil && (*f)() {
		return nil
	}
	return current.Load()
}

// SetOff installs the operator's switch: while fn reports true, Active is
// nil.  Asked on every call, so a settings save takes effect at once; the
// daemon passes a read of its live settings, a one-shot command the value it
// loaded.  nil removes the switch.
func SetOff(fn func() bool) {
	if fn == nil {
		off.Store(nil)
		return
	}
	off.Store(&fn)
}

// Set installs t (nil clears).  For the sync, the loader and tests.
func Set(t *Table) { current.Store(t) }

// Parse decodes and compiles a document.
func Parse(body []byte) (*Table, error) {
	var doc Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return Compile(doc)
}

// LoadDir installs the copy kept in dir, if there is one.  A missing file is
// not an error: the relay list is simply not known yet.
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
// one older than the table in use (a replayed signed document), and one with
// less than MinRetention of its prefixes.
func Ingest(dir string, body []byte) (*Table, error) {
	t, err := Parse(body)
	if err != nil {
		return nil, err
	}
	if cur := Current(); cur != nil {
		if !t.GeneratedAt.IsZero() && t.GeneratedAt.Before(cur.GeneratedAt) {
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

// Name is the relay's display name.
func Name(id string) string {
	if n, ok := Names[id]; ok {
		return n
	}
	return id
}
