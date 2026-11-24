// Package hll is a small HyperLogLog distinct-count estimator (precision
// p=10 -> 1024 registers, ~3.25% standard error).
//
// Unlike COUNT(DISTINCT ...), HLL sketches *merge*: per-minute sketches roll
// up into a window estimate without re-scanning raw rows.  The 1024-byte
// register array is its own on-disk form (stored as a BLOB).
//
// It is used by the nginx-log pipeline to make the dashboard's "unique
// clients" / "unique non-human clients" figures aggregatable across time
// buckets.
package hll

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
)

const (
	p = 10
	m = 1 << p // 1024 registers
	// Size is the on-disk / in-memory byte length of a sketch.
	Size = m
	// maxRank is the largest value Add can put in a register: the sentinel
	// bit bounds the leading zeros at 64-p.
	maxRank = 64 - p + 1
)

// Sketch is a HyperLogLog register array.  The zero value is a valid empty
// sketch (= 0 distinct).
type Sketch [m]byte

// hash maps a key blob to a stable 64-bit value.  SHA-256 (not hash/maphash,
// which seeds randomly per process) so a sketch written by one process still
// merges correctly with another's after a restart.
func hash(b []byte) uint64 {
	s := sha256.Sum256(b)
	return binary.BigEndian.Uint64(s[:8])
}

// Add folds one key (e.g. an IP address) into the sketch.
func (s *Sketch) Add(key []byte) {
	x := hash(key)
	j := x >> (64 - p) // top p bits select the register
	// Shift the remaining bits up and OR a sentinel so the rank is bounded
	// (1..64-p+1) and LeadingZeros never sees an all-zero word.
	w := (x << p) | (1 << (p - 1))
	if rank := byte(bits.LeadingZeros64(w) + 1); rank > s[j] {
		s[j] = rank
	}
}

// Merge takes the register-wise max -- the union of two sketches.
func (s *Sketch) Merge(o *Sketch) {
	for i := range s {
		if o[i] > s[i] {
			s[i] = o[i]
		}
	}
}

// Estimate returns the approximate distinct count.
func (s *Sketch) Estimate() int {
	sum := 0.0
	zeros := 0
	for _, r := range s {
		// A register no Add can have written -- a stored row gone wrong --
		// is read as the largest one can.  Left as it is, a value of 64 or
		// more shifts the one out of the word: the term is 1/0, the sum is
		// infinite, and every window the row is merged into estimates 0.
		if r > maxRank {
			r = maxRank
		}
		sum += 1.0 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	alpha := 0.7213 / (1.0 + 1.079/float64(m))
	est := alpha * float64(m) * float64(m) / sum
	// Small-range correction: linear counting while many registers are still
	// empty.  The 64-bit hash makes the large-range correction unnecessary.
	if est <= 2.5*float64(m) && zeros > 0 {
		est = float64(m) * math.Log(float64(m)/float64(zeros))
	}
	// Registers that are all at the top give a figure past what an int
	// holds, and the conversion of such a float is not defined (it came out
	// negative).  No count of clients is near this bound.
	if est > 1<<53 {
		return 1 << 53
	}
	return int(est + 0.5)
}

// Bytes returns the sketch's on-disk form (a Size-byte slice backed by s).
func (s *Sketch) Bytes() []byte { return s[:] }

// The compact form: a sketch with few registers set -- a bucket that saw a
// handful of addresses, the usual case where a row is kept per site and
// hour -- stored as those registers alone.  A tag byte, then for each set
// register its index (two bytes, big-endian) and its value.  It is written
// only while it is shorter than the array, so a stored sketch of Size bytes
// is the array and any other length the compact form: Load and MergeBytes
// read both.
const compactTag = 1

// Compact returns the sketch's shortest stored form: the set registers while
// that is shorter than the array, the array (Bytes) otherwise.
func (s *Sketch) Compact() []byte {
	k := 0
	for _, r := range s {
		if r != 0 {
			k++
		}
	}
	if 1+3*k >= Size {
		return s.Bytes()
	}
	out := make([]byte, 1, 1+3*k)
	out[0] = compactTag
	for i, r := range s {
		if r != 0 {
			out = append(out, byte(i>>8), byte(i), r)
		}
	}
	return out
}

// compact reports whether a stored sketch is in the compact form.
func compact(b []byte) bool {
	return len(b) != Size && len(b) > 0 && b[0] == compactTag && (len(b)-1)%3 == 0
}

// MergeBytes merges a stored sketch, in either form, into s: Merge(Load(b))
// without the second sketch, for a loop over many rows.
func (s *Sketch) MergeBytes(b []byte) {
	if compact(b) {
		for j := 1; j+2 < len(b); j += 3 {
			// An index past the array is a stored row gone wrong: skipped.
			if i := int(b[j])<<8 | int(b[j+1]); i < m && b[j+2] > s[i] {
				s[i] = b[j+2]
			}
		}
		return
	}
	for i := 0; i < len(b) && i < m; i++ {
		if b[i] > s[i] {
			s[i] = b[i]
		}
	}
}

// Empty reports whether the sketch has had nothing added (= 0 distinct).
func (s *Sketch) Empty() bool { return *s == Sketch{} }

// Load reconstructs a sketch from its stored BLOB form, the array or the
// compact form.  An empty blob yields an empty sketch (= 0 distinct).
func Load(b []byte) *Sketch {
	var s Sketch
	s.MergeBytes(b)
	return &s
}
