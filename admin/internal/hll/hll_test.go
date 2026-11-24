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

// TestOutOfRangeRegisterDoesNotZeroTheEstimate: a stored sketch with a
// register no Add can write (the largest is maxRank) -- one byte of one row
// gone wrong -- used to turn every window it was merged into to an estimate
// of 0: a register of 64 or more shifts the one out of the word and the
// harmonic sum becomes infinite.  It is read as the largest valid register,
// which moves the estimate by about a thousandth.
func TestOutOfRangeRegisterDoesNotZeroTheEstimate(t *testing.T) {
	var good Sketch
	for i := 0; i < 50000; i++ {
		good.Add([]byte(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)))
	}
	want := good.Estimate()
	for _, r := range []byte{maxRank + 1, 63, 64, 200, 255} {
		bad := make([]byte, Size)
		bad[17] = r
		merged := good
		merged.Merge(Load(bad))
		got := merged.Estimate()
		if diff := float64(got-want) / float64(want); diff < -0.01 || diff > 0.01 {
			t.Errorf("merged with a row whose register reads %d: estimate %d, want about %d", r, got, want)
		}
	}
	// A sketch made of nothing but such registers still estimates a number:
	// a large one, not the negative an overflowing conversion gave.
	var all Sketch
	for i := range all {
		all[i] = 255
	}
	if got := all.Estimate(); got != 1<<53 {
		t.Errorf("a sketch of out-of-range registers estimates %d, want the bound %d", got, 1<<53)
	}
}

// TestCompactRoundTrips: the compact form holds the set registers and comes
// back as the same sketch, through Load and through MergeBytes, at every
// fill -- and it is never Size bytes long, which is how a reader tells the two
// forms apart.  Past the point where it would not be shorter, the array is
// what is written.
func TestCompactRoundTrips(t *testing.T) {
	for _, n := range []int{0, 1, 2, 10, 100, 250, 400, 1000, 10000} {
		var s Sketch
		for i := 0; i < n; i++ {
			s.Add([]byte(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		}
		set := 0
		for _, r := range s {
			if r != 0 {
				set++
			}
		}
		b := s.Compact()
		switch {
		case 1+3*set < Size:
			if len(b) != 1+3*set || b[0] != compactTag {
				t.Errorf("n=%d (%d registers set): compact form of %d bytes, want %d", n, set, len(b), 1+3*set)
			}
		default:
			if len(b) != Size {
				t.Errorf("n=%d (%d registers set): %d bytes written, want the %d-byte array", n, set, len(b), Size)
			}
		}
		if got := Load(b); *got != s {
			t.Errorf("n=%d: Load of the stored form is not the sketch", n)
		}
		var m1 Sketch
		m1.MergeBytes(b)
		if m1 != s {
			t.Errorf("n=%d: MergeBytes into an empty sketch is not the sketch", n)
		}
		// Merging the stored form into another sketch is the union.
		var o, want Sketch
		o.Add([]byte("another"))
		want = o
		want.Merge(&s)
		o.MergeBytes(b)
		if o != want {
			t.Errorf("n=%d: MergeBytes is not Merge", n)
		}
		if got, wantN := Load(b).Estimate(), s.Estimate(); got != wantN {
			t.Errorf("n=%d: estimate %d after a round trip, want %d", n, got, wantN)
		}
	}
	// The array as stored before the compact form existed reads as before.
	var s Sketch
	s.Add([]byte("x"))
	if got := Load(s.Bytes()); *got != s {
		t.Error("the array form no longer loads")
	}
	if got := Load(nil); !got.Empty() {
		t.Error("an empty blob is not an empty sketch")
	}
	// A compact row gone wrong -- an index past the array -- is skipped, not
	// a panic.
	if got := Load([]byte{compactTag, 0xff, 0xff, 3, 0, 1, 2}); got[1] != 2 {
		t.Errorf("a compact row with a bad index: register 1 is %d, want 2", got[1])
	}
}
