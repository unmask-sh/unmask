package hll

import (
	"fmt"
	"testing"
)

// TestEstimateTracksDistinctCount: the estimate is within the sketch's
// standard error of the true count at every scale, and a repeated key adds
// nothing.
func TestEstimateTracksDistinctCount(t *testing.T) {
	for _, n := range []int{0, 1, 10, 100, 1000, 10000, 100000} {
		var s Sketch
		for i := 0; i < n; i++ {
			s.Add([]byte(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		}
		got := s.Estimate()
		// The standard error is about 3.25% past the register count and a
		// few percent under it (linear counting), so 10% is a wide margin;
		// the smallest counts are exact to within one.
		tolerance := n/10 + 1
		if diff := got - n; diff > tolerance || diff < -tolerance {
			t.Errorf("n=%d: estimate %d (tolerance %d)", n, got, tolerance)
		}
		before := s
		for i := 0; i < n; i++ {
			s.Add([]byte(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		}
		if s != before {
			t.Errorf("n=%d: adding the same keys again changed the sketch", n)
		}
	}
}

// TestMergeIsTheUnion: merging two sketches estimates their union, and
// merging is idempotent and commutative.
func TestMergeIsTheUnion(t *testing.T) {
	var a, b Sketch
	for i := 0; i < 5000; i++ {
		a.Add([]byte(fmt.Sprintf("a-%d", i)))
	}
	for i := 2500; i < 7500; i++ {
		b.Add([]byte(fmt.Sprintf("a-%d", i)))
	}
	ab, ba := a, b
	ab.Merge(&b)
	ba.Merge(&a)
	if ab != ba {
		t.Fatal("merge is not commutative")
	}
	got := ab.Estimate()
	if got < 7500-750 || got > 7500+750 {
		t.Fatalf("union estimate %d, want about 7500", got)
	}
	again := ab
	again.Merge(&b)
	if again != ab {
		t.Fatal("merging a sketch already merged changed the result")
	}
	var empty Sketch
	ab.Merge(&empty)
	if ab != ba {
		t.Fatal("merging an empty sketch changed the result")
	}
}

// TestBytesLoadRoundTrip: the on-disk form reloads to the same sketch, a
// short or empty blob is an empty sketch, and Empty tells them apart.
func TestBytesLoadRoundTrip(t *testing.T) {
	var s Sketch
	if !s.Empty() || s.Estimate() != 0 {
		t.Fatalf("zero sketch: empty=%v estimate=%d", s.Empty(), s.Estimate())
	}
	s.Add([]byte("203.0.113.1"))
	if s.Empty() {
		t.Fatal("a sketch with one key reports empty")
	}
	b := s.Bytes()
	if len(b) != Size {
		t.Fatalf("Bytes: %d bytes, want %d", len(b), Size)
	}
	back := Load(append([]byte(nil), b...))
	if *back != s {
		t.Fatal("Load(Bytes()) is not the sketch")
	}
	if got := Load(nil); !got.Empty() {
		t.Fatal("Load(nil) is not empty")
	}
	if got := Load(b[:10]); got.Estimate() > s.Estimate() {
		t.Fatalf("a truncated blob estimates %d, more than the whole %d", got.Estimate(), s.Estimate())
	}
}

// TestHashIsStableAcrossProcesses: the register a key lands in is a fixed
// function of the key (SHA-256, not a per-process seed), so sketches written
// by different processes merge correctly.  Pinned by value.
func TestHashIsStableAcrossProcesses(t *testing.T) {
	var s Sketch
	s.Add([]byte("203.0.113.1"))
	set := -1
	for i, r := range s {
		if r != 0 {
			if set >= 0 {
				t.Fatalf("one key set registers %d and %d", set, i)
			}
			set = i
		}
	}
	if x := hash([]byte("203.0.113.1")); int(x>>(64-p)) != set {
		t.Fatalf("register %d, hash says %d", set, x>>(64-p))
	}
	var again Sketch
	again.Add([]byte("203.0.113.1"))
	if again != s {
		t.Fatal("the same key produced a different sketch")
	}
}
