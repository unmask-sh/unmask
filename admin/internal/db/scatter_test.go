package db

import (
	"math"
	"testing"
)

// A file that is largely free pages leaves its tables scattered, and a build
// reads them a page at a time: the built-in disk rates are scaled by the file
// over its live pages, from where doctor advises a compaction, up to a cap.
// On a large install (2026-09-29) a file more than half free built two and a
// half times slower than estimated.
func TestScatterFactor(t *testing.T) {
	const gb = int64(1) << 30
	for _, c := range []struct {
		name       string
		file, live int64
		want       float64
	}{
		{"compact", 36 * gb, 36 * gb, 1},
		{"a little free", 36 * gb, 30 * gb, 1},                     // a sixth free: under a quarter
		{"small file, half free", gb, gb / 2, 1},                   // half a gigabyte free: under a gigabyte
		{"more than half free", 363 * gb / 10, 165 * gb / 10, 2.2}, // 36.3 GB, 19.8 GB of it free
		{"a quarter free", 8 * gb, 6 * gb, 8.0 / 6.0},
		{"nearly all free", 40 * gb, 2 * gb, scatterFactorMax},
	} {
		sp := SQLiteSpace{FileBytes: c.file, LiveBytes: c.live, PageSize: 4096}
		if got := scatterFactor(sp); math.Abs(got-c.want) > 0.01 {
			t.Errorf("%s: scatterFactor = %.3f, want %.3f", c.name, got, c.want)
		}
		if got, want := sp.Scattered(), c.want > 1; got != want {
			t.Errorf("%s: Scattered = %v, want %v", c.name, got, want)
		}
	}
}
