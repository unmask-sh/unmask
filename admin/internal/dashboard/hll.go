package dashboard

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
)

// hll is a HyperLogLog distinct-count estimator (precision p=10 → 1024
// registers, ~3.25% standard error). It makes the per-verdict / per-country
// distinct-IP figures aggregatable: unlike COUNT(DISTINCT ip_address), HLL
// sketches merge, so per-hour / per-day sketches roll up into a window
// estimate without re-scanning raw events. The 1024-byte register array is
// its own on-disk form (stored as a BLOB in unmask_aggregate_hll).
const (
	hllP = 10
	hllM = 1 << hllP // 1024 registers
)

type hll [hllM]byte

// hllHash maps an ip_address blob to a stable 64-bit value. SHA-256 (not
// hash/maphash, which seeds randomly per process) so a sketch written by one
// process still merges correctly with another's after a restart.
func hllHash(b []byte) uint64 {
	s := sha256.Sum256(b)
	return binary.BigEndian.Uint64(s[:8])
}

// add folds one ip_address into the sketch.
func (h *hll) add(ip []byte) {
	x := hllHash(ip)
	j := x >> (64 - hllP) // top p bits select the register
	// Shift the remaining bits up and OR a sentinel so the rank is bounded
	// (1..64-p+1) and LeadingZeros never sees an all-zero word.
	w := (x << hllP) | (1 << (hllP - 1))
	if rank := byte(bits.LeadingZeros64(w) + 1); rank > h[j] {
		h[j] = rank
	}
}

// merge takes the register-wise max — the union of two sketches.
func (h *hll) merge(o *hll) {
	for i := range h {
		if o[i] > h[i] {
			h[i] = o[i]
		}
	}
}

// estimate returns the approximate distinct count.
func (h *hll) estimate() int {
	sum := 0.0
	zeros := 0
	for _, r := range h {
		sum += 1.0 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	alpha := 0.7213 / (1.0 + 1.079/float64(hllM))
	est := alpha * float64(hllM) * float64(hllM) / sum
	// Small-range correction: linear counting while many registers are still
	// empty. The 64-bit hash makes the large-range correction unnecessary.
	if est <= 2.5*float64(hllM) && zeros > 0 {
		est = float64(hllM) * math.Log(float64(hllM)/float64(zeros))
	}
	return int(est + 0.5)
}

// loadHLL reconstructs a sketch from its stored BLOB form. A short / empty
// blob yields an empty sketch (= 0 distinct).
func loadHLL(b []byte) *hll {
	var h hll
	copy(h[:], b)
	return &h
}
