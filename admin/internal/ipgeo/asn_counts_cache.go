package ipgeo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ASNCounts walks the whole ASN database -- a second or more of CPU -- and
// the settings page asked for it on every render of every tab through
// 0.1.53 (seven tenths of the page's CPU; under load the render outran the
// server's write timeout and the browser got half a page, without its save
// button).  The answer changes only when the database file does or the
// catalogue of providers does, so it is kept here by both: the file's path,
// size and modification time, and a digest of the patterns and numbers
// asked about.  A few entries at most (asnCountsMemoMax): the catalogue is
// one, and a file replaced by the auto-update is a new key, not a growing
// map.  One walk at a time: a render that finds another computing the same
// key waits for it and takes its answer.

type asnCountsKey struct {
	path   string
	size   int64
	mtime  int64 // unix nanoseconds
	inputs string
}

const asnCountsMemoMax = 8

var (
	asnCountsMu   sync.RWMutex
	asnCountsMemo = map[asnCountsKey]map[string]int{}
	// asnCountsWalk serialises the walks: the second render of the same
	// database waits for the first and reads what it kept.
	asnCountsWalk sync.Mutex
)

// ASNCountsCached is ASNCounts memoized on the database's identity and the
// question's digest.  The map returned is the caller's own copy.
func ASNCountsCached(path string, orgPatternsByKey map[string][]string, asnsByKey map[string][]uint) (map[string]int, error) {
	if path == "" || (len(orgPatternsByKey) == 0 && len(asnsByKey) == 0) {
		return map[string]int{}, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	key := asnCountsKey{path: path, size: fi.Size(), mtime: fi.ModTime().UnixNano(), inputs: asnCountsInputs(orgPatternsByKey, asnsByKey)}
	if v, ok := asnCountsLookup(key); ok {
		return v, nil
	}
	asnCountsWalk.Lock()
	defer asnCountsWalk.Unlock()
	if v, ok := asnCountsLookup(key); ok {
		return v, nil
	}
	counts, err := ASNCounts(path, orgPatternsByKey, asnsByKey)
	if err != nil {
		return nil, err
	}
	asnCountsMu.Lock()
	if len(asnCountsMemo) >= asnCountsMemoMax {
		asnCountsMemo = map[asnCountsKey]map[string]int{}
	}
	asnCountsMemo[key] = counts
	asnCountsMu.Unlock()
	return copyCounts(counts), nil
}

func asnCountsLookup(key asnCountsKey) (map[string]int, bool) {
	asnCountsMu.RLock()
	defer asnCountsMu.RUnlock()
	v, ok := asnCountsMemo[key]
	if !ok {
		return nil, false
	}
	return copyCounts(v), true
}

func copyCounts(v map[string]int) map[string]int {
	out := make(map[string]int, len(v))
	for k, n := range v {
		out[k] = n
	}
	return out
}

// asnCountsInputs digests the question: every key with its patterns and
// numbers, in a fixed order.
func asnCountsInputs(orgPatternsByKey map[string][]string, asnsByKey map[string][]uint) string {
	keys := map[string]bool{}
	for k := range orgPatternsByKey {
		keys[k] = true
	}
	for k := range asnsByKey {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	h := sha256.New()
	for _, k := range sorted {
		h.Write([]byte(k))
		h.Write([]byte{0})
		pats := append([]string(nil), orgPatternsByKey[k]...)
		sort.Strings(pats)
		h.Write([]byte(strings.Join(pats, "\x01")))
		h.Write([]byte{0})
		nums := append([]uint(nil), asnsByKey[k]...)
		sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
		for _, n := range nums {
			h.Write([]byte(strconv.FormatUint(uint64(n), 10)))
			h.Write([]byte{2})
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ASNCountsMemoReset forgets what is kept (the tests).
func ASNCountsMemoReset() {
	asnCountsMu.Lock()
	asnCountsMemo = map[asnCountsKey]map[string]int{}
	asnCountsMu.Unlock()
}
