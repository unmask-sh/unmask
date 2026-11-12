// crawler_range.go: whether a request carrying a crawler's name came from the
// addresses that crawler's vendor publishes.
//
// The per-crawler counters say how often a name was seen; a name is free to
// claim, so the count alone cannot tell the vendor's crawler from a client
// wearing its User-Agent.  For the vendors that publish their ranges
// (UARangePresets) the address answers it, and the access-log reader asks
// here for every crawler line it counts.
//
// The answer is a fact about the request, not about the configuration: the
// ranges are the vendor's as loaded (the shipped snapshot or a pulled copy),
// whether or not the operator enabled the preset that bypasses them.  With
// the preset off, the genuine crawler is still told from the impostor in the
// counters; only what nginx does with either differs.
package nginxconf

import (
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/classify"
)

// crawlerRangeSet is the presets backing one crawler name: their ids, and
// the ids joined as the key its prefix index is kept under.  Crawlers of one
// vendor share a set (every Google crawler rides the same three files), and
// so share an index.
type crawlerRangeSet struct {
	ids []string
	key string
}

var (
	crawlerRangeOnce sync.Once
	crawlerRangeSets map[string]crawlerRangeSet // crawler display name -> its presets

	// crawlerRangeIdx holds the prefix index of every set asked for since
	// the ranges were last loaded; crawlerRangeGen is that load
	// (IPRangeGeneration).  A pull or an override file replaces the ranges
	// under the indexes, so they are dropped together when it moves.
	crawlerRangeMu  sync.RWMutex
	crawlerRangeGen uint64
	crawlerRangeIdx map[string]*prefixIndex
)

// crawlerRangeByName folds UARangePresets to the names the per-crawler
// aggregation keys on (classify.CrawlerNameFromPattern).  Built once: the
// table does not change while the process runs.  Two patterns folding to one
// name pool their presets.
func crawlerRangeByName() map[string]crawlerRangeSet {
	crawlerRangeOnce.Do(func() {
		ids := map[string]map[string]bool{}
		for pat, presets := range UARangePresets {
			name := classify.CrawlerNameFromPattern(pat)
			if name == "" || name == "other" {
				continue
			}
			if ids[name] == nil {
				ids[name] = map[string]bool{}
			}
			for _, id := range presets {
				ids[name][id] = true
			}
		}
		crawlerRangeSets = make(map[string]crawlerRangeSet, len(ids))
		for name, set := range ids {
			list := make([]string, 0, len(set))
			for id := range set {
				list = append(list, id)
			}
			sort.Strings(list)
			crawlerRangeSets[name] = crawlerRangeSet{ids: list, key: strings.Join(list, ",")}
		}
	})
	return crawlerRangeSets
}

// CrawlerVendorRange reports, for a crawler by the name the per-crawler
// aggregation keys on, whether its vendor publishes address ranges at all
// (published) and whether ip is inside them (inRange).  The ranges are the
// ones loaded for the presets backing the name, enabled or not.  An empty or
// unparseable ip is never in range.  Safe for concurrent use.
func CrawlerVendorRange(name, ip string) (published, inRange bool) {
	set, ok := crawlerRangeByName()[name]
	if !ok {
		return false, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return true, false
	}
	return true, crawlerRangeIndex(set).contains(addr)
}

// crawlerRangeIndex returns the prefix index of a set, built on first use and
// again once the ranges have been loaded anew.
func crawlerRangeIndex(set crawlerRangeSet) *prefixIndex {
	gen := IPRangeGeneration()
	crawlerRangeMu.RLock()
	if crawlerRangeGen == gen {
		if x := crawlerRangeIdx[set.key]; x != nil {
			crawlerRangeMu.RUnlock()
			return x
		}
	}
	crawlerRangeMu.RUnlock()

	// Built outside the lock: a vendor's list runs to over a thousand
	// prefixes, and the readers of the other sets need not wait for the parse.
	//
	// The list has to be the one of the generation it is kept under.  A
	// reload (Reload, SetOverrideDir) empties the groups and leaves the load
	// to the next reader, so a list read across one can be a newer one or,
	// for an instant, an empty one -- and an index built from that would call
	// every request of the vendor's out of range until the next reload.  A
	// reload shows as a generation that moved by the time the list is in
	// hand: the build is then done over.  Reloads are hours apart, so the
	// second try settles it; the bound is for a caller that reloads in a
	// loop, whose index is used for the one answer and not kept.
	var x *prefixIndex
	settled := false
	for try := 0; try < 4 && !settled; try++ {
		x = newPrefixIndex(FlattenBypassPresets(set.ids))
		now := IPRangeGeneration()
		settled = now == gen
		gen = now
	}
	if !settled {
		return x
	}
	crawlerRangeMu.Lock()
	defer crawlerRangeMu.Unlock()
	switch {
	case gen < crawlerRangeGen:
		// The ranges were loaded again while this one was being built, and
		// someone has already started over: answer from it once, keep nothing.
		return x
	case gen > crawlerRangeGen || crawlerRangeIdx == nil:
		crawlerRangeIdx, crawlerRangeGen = map[string]*prefixIndex{}, gen
	}
	crawlerRangeIdx[set.key] = x
	return x
}

// prefixIndex answers "is this address inside any of these prefixes" without
// walking them.  The masked network addresses are kept in one set per prefix
// length present; a lookup masks the address to each of those lengths and
// asks the set.  A vendor's list has over a thousand prefixes and a handful
// of lengths, and the access-log reader asks once for every crawler line.
type prefixIndex struct {
	v4, v6 []prefixLen
}

// prefixLen is the networks of one prefix length.
type prefixLen struct {
	bits int
	nets map[netip.Addr]struct{}
}

// newPrefixIndex indexes the prefixes as the range files write them: CIDR
// blocks, or bare addresses (one vendor lists hosts), which count as their
// own /32 or /128.  A v4-mapped block is filed with the IPv4 ones it spells.
// An entry that does not parse is left out.
func newPrefixIndex(prefixes []string) *prefixIndex {
	v4, v6 := map[int]map[netip.Addr]struct{}{}, map[int]map[netip.Addr]struct{}{}
	for _, s := range prefixes {
		s = strings.TrimSpace(s)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				continue
			}
			a = a.Unmap().WithZone("")
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = unmapPrefix(p)
		byLen := v6
		if p.Addr().Is4() {
			byLen = v4
		}
		if byLen[p.Bits()] == nil {
			byLen[p.Bits()] = map[netip.Addr]struct{}{}
		}
		byLen[p.Bits()][p.Addr()] = struct{}{}
	}
	return &prefixIndex{v4: prefixLens(v4), v6: prefixLens(v6)}
}

// prefixLens lays the per-length sets out as a slice, longest prefix first
// (a fixed order; any hit answers the question).
func prefixLens(byLen map[int]map[netip.Addr]struct{}) []prefixLen {
	out := make([]prefixLen, 0, len(byLen))
	for bits, nets := range byLen {
		out = append(out, prefixLen{bits: bits, nets: nets})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bits > out[j].bits })
	return out
}

// contains reports whether addr is inside any indexed prefix.  A v4-mapped
// IPv6 address is looked up as the IPv4 address it carries.
func (x *prefixIndex) contains(addr netip.Addr) bool {
	if x == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	lens := x.v6
	if addr.Is4() {
		lens = x.v4
	}
	for _, l := range lens {
		p, err := addr.Prefix(l.bits)
		if err != nil {
			continue
		}
		if _, ok := l.nets[p.Addr()]; ok {
			return true
		}
	}
	return false
}
