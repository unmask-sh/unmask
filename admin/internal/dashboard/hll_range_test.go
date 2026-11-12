package dashboard

import (
	"fmt"
	"testing"
)

// The dashboard's own sketch reads an out-of-range register the way
// internal/hll does: as the largest valid one, not as a division by zero
// that turns the estimate of every window holding the row into 0.
func TestHLLOutOfRangeRegisterDoesNotZeroTheEstimate(t *testing.T) {
	var good hll
	for i := 0; i < 50000; i++ {
		good.add([]byte(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)))
	}
	want := good.estimate()
	for _, r := range []byte{hllMaxRank + 1, 64, 200} {
		bad := make([]byte, hllM)
		bad[17] = r
		merged := good
		merged.mergeBytes(bad)
		got := merged.estimate()
		if diff := float64(got-want) / float64(want); diff < -0.01 || diff > 0.01 {
			t.Errorf("merged with a row whose register reads %d: estimate %d, want about %d", r, got, want)
		}
	}
}
