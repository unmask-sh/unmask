package ipgeo

import (
	"sort"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// ASN-suggestion support for the settings UI custom-rule input.  An operator
// types a fragment; we answer from the *real* installed ASN mmdb (not a curated
// list), so coverage is whatever the DB knows.  Two query shapes:
//
//   - text  ("microsoft", "ovh")   -> organizations whose name contains it,
//     ranked by IPv4 space, each carrying its member AS numbers (elided).
//   - number ("16509", "AS16509")  -> the exact AS number, pinpointed to its
//     org; a short numeric prefix ("165") also surfaces prefix matches.
//
// The index is built once by walking the mmdb and kept immutable, so per-query
// search is a linear scan over ~70k orgs (sub-millisecond) with no DB I/O.

// maxOrgASNs caps how many member AS numbers a text suggestion carries; the rest
// are summarized as ASNMore so a huge provider (Azure, AWS) does not bloat the
// payload.  "ある程度で省略してもいい" per the operator.
const maxOrgASNs = 8

// ASNSuggestion is one candidate row for the custom-rule autocomplete.
type ASNSuggestion struct {
	Kind    string `json:"kind"`     // "org" | "asn"
	Value   string `json:"value"`    // what to write into the rule: org name, or "AS<n>"
	Org     string `json:"org"`      // organization display name
	ASN     uint   `json:"asn"`      // exact AS number (kind=="asn")
	ASNs    []uint `json:"asns"`     // member AS numbers, size-desc (kind=="org")
	ASNMore int    `json:"asn_more"` // member ASNs beyond ASNs (0 if none omitted)
	Size24  uint64 `json:"size24"`   // total IPv4 space, in /24-equivalents
}

type asnOrgEntry struct {
	org    string
	orgLow string
	asns   []uint // member AS numbers, sorted by IPv4 size desc
	size24 uint64 // total IPv4 /24-equivalents across the org
}

// asnLoc pins an AS number to its org (index into orgs) and its own IPv4 size,
// so a numeric pinpoint reports the AS's space, not the whole org's.
type asnLoc struct {
	org    int
	size24 uint64
}

type asnSuggestIndex struct {
	orgs    []asnOrgEntry
	byASN   map[uint]asnLoc // AS number -> its org + own size (larger org wins on collision)
	asnNums []uint          // every known AS number, ascending, for numeric prefix scan
}

// SuggestASN answers an autocomplete query from the installed ASN mmdb.  Returns
// nil when no ASN DB is loaded or the query is too short.  Builds the index on
// first call (lazy: startup stays fast; the settings page is the only caller).
func (r *Reader) SuggestASN(q string, limit int) []ASNSuggestion {
	if r == nil {
		return nil
	}
	q = strings.TrimSpace(q)
	if q == "" || limit <= 0 {
		return nil
	}
	idx := r.asnIndexOrBuild()
	if idx == nil {
		return nil
	}
	return idx.search(q, limit)
}

// asnIndexOrBuild returns the cached index, building it under the lock on first
// use.  The build walks the whole ASN mmdb once (~70k orgs); subsequent calls
// are free.
func (r *Reader) asnIndexOrBuild() *asnSuggestIndex {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asnIdx != nil {
		return r.asnIdx
	}
	if r.asnDB == nil {
		return nil
	}
	r.asnIdx = buildASNSuggestIndex(r.asnDB)
	return r.asnIdx
}

func buildASNSuggestIndex(db *maxminddb.Reader) *asnSuggestIndex {
	type agg struct {
		asnSize map[uint]uint64 // per-AS IPv4 /24-equivalents (for member ordering)
		total   uint64
	}
	byOrg := map[string]*agg{}
	var rec struct {
		ASN uint   `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}
	nets := db.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		cidr, err := nets.Network(&rec)
		if err != nil || rec.Org == "" {
			continue
		}
		var sz uint64
		if ones, bits := cidr.Mask.Size(); bits == 32 {
			sz = uint64(1) << uint(32-ones) / 256 // /24-equivalents
			if sz == 0 {
				sz = 1 // sub-/24 blocks still count as one
			}
		}
		a := byOrg[rec.Org]
		if a == nil {
			a = &agg{asnSize: map[uint]uint64{}}
			byOrg[rec.Org] = a
		}
		a.total += sz
		if rec.ASN != 0 {
			a.asnSize[rec.ASN] += sz
		}
	}
	if err := nets.Err(); err != nil && len(byOrg) == 0 {
		return &asnSuggestIndex{byASN: map[uint]asnLoc{}}
	}

	idx := &asnSuggestIndex{byASN: map[uint]asnLoc{}}
	for org, a := range byOrg {
		asns := make([]uint, 0, len(a.asnSize))
		for n := range a.asnSize {
			asns = append(asns, n)
		}
		// Member ASNs: biggest first, ties broken by number for stable output.
		sort.Slice(asns, func(i, j int) bool {
			if a.asnSize[asns[i]] != a.asnSize[asns[j]] {
				return a.asnSize[asns[i]] > a.asnSize[asns[j]]
			}
			return asns[i] < asns[j]
		})
		ei := len(idx.orgs)
		idx.orgs = append(idx.orgs, asnOrgEntry{
			org:    org,
			orgLow: strings.ToLower(org),
			asns:   asns,
			size24: a.total,
		})
		for _, n := range asns {
			// On collision keep the AS number's larger org (by total space).
			if prev, ok := idx.byASN[n]; ok && idx.orgs[prev.org].size24 >= a.total {
				continue
			}
			idx.byASN[n] = asnLoc{org: ei, size24: a.asnSize[n]}
		}
	}
	idx.asnNums = make([]uint, 0, len(idx.byASN))
	for n := range idx.byASN {
		idx.asnNums = append(idx.asnNums, n)
	}
	sort.Slice(idx.asnNums, func(i, j int) bool { return idx.asnNums[i] < idx.asnNums[j] })
	return idx
}

// search dispatches on the query shape.  A query that is all digits (after an
// optional "AS"/"as" prefix) is numeric; anything else is a text/org search.
func (x *asnSuggestIndex) search(q string, limit int) []ASNSuggestion {
	num := strings.TrimSpace(q)
	if l := strings.ToLower(num); strings.HasPrefix(l, "as") {
		num = num[2:]
	}
	if num != "" && isAllDigits(num) {
		return x.searchNumber(num, limit)
	}
	return x.searchOrg(q, limit)
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// searchNumber pinpoints an exact AS number, then fills with numeric-prefix
// matches (e.g. "165" -> AS165, AS1650, ...) ascending.
func (x *asnSuggestIndex) searchNumber(digits string, limit int) []ASNSuggestion {
	out := make([]ASNSuggestion, 0, limit)
	seen := map[uint]bool{}

	if n, err := strconv.ParseUint(digits, 10, 32); err == nil {
		if loc, ok := x.byASN[uint(n)]; ok {
			out = append(out, x.asnSuggestion(uint(n), loc))
			seen[uint(n)] = true
		}
	}
	// Prefix matches on the decimal AS number string.
	for _, n := range x.asnNums {
		if len(out) >= limit {
			break
		}
		if seen[n] {
			continue
		}
		if strings.HasPrefix(strconv.FormatUint(uint64(n), 10), digits) {
			out = append(out, x.asnSuggestion(n, x.byASN[n]))
		}
	}
	return out
}

func (x *asnSuggestIndex) asnSuggestion(n uint, loc asnLoc) ASNSuggestion {
	return ASNSuggestion{
		Kind:   "asn",
		Value:  "AS" + strconv.FormatUint(uint64(n), 10),
		Org:    x.orgs[loc.org].org,
		ASN:    n,
		Size24: loc.size24,
	}
}

// searchOrg returns organizations whose name contains the query, ranked by
// IPv4 space, each carrying up to maxOrgASNs member AS numbers.
func (x *asnSuggestIndex) searchOrg(q string, limit int) []ASNSuggestion {
	low := strings.ToLower(strings.TrimSpace(q))
	if low == "" {
		return nil
	}
	return x.rankOrgs(func(orgLow string) bool { return strings.Contains(orgLow, low) }, limit)
}

// searchOrgAnd returns organizations whose name contains ALL of the given
// (already-lowercased, non-empty) terms -- the space-separated AND filter that
// narrows within a provider, e.g. ["amazon","data"] -> "Amazon Data Services".
func (x *asnSuggestIndex) searchOrgAnd(lows []string, limit int) []ASNSuggestion {
	if len(lows) == 0 {
		return nil
	}
	return x.rankOrgs(func(orgLow string) bool {
		for _, t := range lows {
			if !strings.Contains(orgLow, t) {
				return false
			}
		}
		return true
	}, limit)
}

// rankOrgs collects orgs matching pred, ranks them by IPv4 size, and renders the
// top `limit` as org suggestions (member AS numbers elided past maxOrgASNs).
func (x *asnSuggestIndex) rankOrgs(pred func(orgLow string) bool, limit int) []ASNSuggestion {
	type hit struct {
		ei     int
		size24 uint64
	}
	var hits []hit
	for i := range x.orgs {
		if pred(x.orgs[i].orgLow) {
			hits = append(hits, hit{i, x.orgs[i].size24})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].size24 != hits[j].size24 {
			return hits[i].size24 > hits[j].size24
		}
		return x.orgs[hits[i].ei].org < x.orgs[hits[j].ei].org
	})
	out := make([]ASNSuggestion, 0, limit)
	for _, h := range hits {
		if len(out) >= limit {
			break
		}
		out = append(out, x.orgSuggestion(h.ei))
	}
	return out
}

// orgSuggestion renders one org entry as an "org" suggestion, eliding member AS
// numbers past maxOrgASNs.
func (x *asnSuggestIndex) orgSuggestion(ei int) ASNSuggestion {
	e := x.orgs[ei]
	shown := e.asns
	more := 0
	if len(shown) > maxOrgASNs {
		more = len(shown) - maxOrgASNs
		shown = shown[:maxOrgASNs]
	}
	asns := make([]uint, len(shown))
	copy(asns, shown)
	return ASNSuggestion{
		Kind:    "org",
		Value:   e.org,
		Org:     e.org,
		ASNs:    asns,
		ASNMore: more,
		Size24:  e.size24,
	}
}

// SuggestASNAnd returns org suggestions whose name contains ALL of the given
// terms (case-insensitive substrings), ranked by IPv4 size.  This is the
// multi-term AND path; single-term / numeric queries use SuggestASN.
func (r *Reader) SuggestASNAnd(terms []string, limit int) []ASNSuggestion {
	if r == nil || limit <= 0 {
		return nil
	}
	lows := make([]string, 0, len(terms))
	for _, t := range terms {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			lows = append(lows, t)
		}
	}
	if len(lows) == 0 {
		return nil
	}
	idx := r.asnIndexOrBuild()
	if idx == nil {
		return nil
	}
	return idx.searchOrgAnd(lows, limit)
}
