package i18n

import (
	"testing"
	"time"
)

// Ago is what the advisor card shows next to a review: the operator reads
// "2 時間前" and knows which run it came from.
func TestAgo(t *testing.T) {
	for _, tc := range []struct {
		d  time.Duration
		ja string
		en string
	}{
		{20 * time.Second, "たった今", "just now"},
		{5 * time.Minute, "5 分前", "5m ago"},
		{2 * time.Hour, "2 時間前", "2h ago"},
		{3 * 24 * time.Hour, "3 日前", "3d ago"},
	} {
		if got := Ago("ja", tc.d); got != tc.ja {
			t.Errorf("ja %v: %q", tc.d, got)
		}
		if got := Ago("en", tc.d); got != tc.en {
			t.Errorf("en %v: %q", tc.d, got)
		}
	}
}
