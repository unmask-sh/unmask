package cookies

import "testing"

// A 3-segment entry is honoured for the window of what it is a pass of.  A
// solved CAPTCHA and the re-bound entry that stands for a solve keep the
// CAPTCHA window; the math fallback's downgraded "pow" and "passthrough" --
// proof-of-work grade, and no proof at all -- keep the proof-of-work window.
// Every kind used to be held to the CAPTCHA window: ten days old, on the
// defaults' seven and fourteen days, all four verified.
func TestThreeSegmentKindsKeepTheirGradesWindow(t *testing.T) {
	const secret, ip, host = "test-secret", "198.51.100.7", "example.com"
	const day = 86400
	now := nowUnix()
	for _, c := range []struct {
		kind         string
		pow, captcha int   // the two windows, in days
		age          int64 // of the entry, in days
		good         bool
	}{
		// The defaults: seven days for a proof-of-work, fourteen for a CAPTCHA.
		{"pow", 7, 14, 6, true},
		{"pow", 7, 14, 10, false},
		{"passthrough", 7, 14, 6, true},
		{"passthrough", 7, 14, 10, false},
		{"captcha", 7, 14, 10, true},
		{"captcha", 7, 14, 15, false},
		{"rebind", 7, 14, 10, true},
		{"rebind", 7, 14, 15, false},
		// An install that keeps a proof-of-work longer than a CAPTCHA: each
		// kind still follows its own window, not the shorter or the longer.
		{"pow", 14, 7, 10, true},
		{"pow", 14, 7, 15, false},
		{"passthrough", 14, 7, 10, true},
		{"captcha", 14, 7, 6, true},
		{"captcha", 14, 7, 10, false},
		{"rebind", 14, 7, 10, false},
	} {
		for _, h := range []SigHash{SigSHA1, SigSHA256, SigSHA256Wide} {
			e := IssueValueAtH(h, secret, ip, host, c.kind, now-c.age*day)
			if got := Verify(e, secret, ip, host, c.pow*day, c.captcha*day, 18); got != c.good {
				t.Errorf("kind %q (%s), %d days old, windows %d / %d days: verifies=%v, want %v", c.kind, h, c.age, c.pow, c.captcha, got, c.good)
			}
			if _, k, _, _, ok := MatchingEntryID(e, secret, ip, host, c.pow*day, c.captcha*day, 18); ok != c.good || (ok && k != c.kind) {
				t.Errorf("kind %q (%s), %d days old: MatchingEntryID ok=%v kind=%q", c.kind, h, c.age, ok, k)
			}
		}
	}
	if kindWindow("pow", 1, 2) != 1 || kindWindow("passthrough", 1, 2) != 1 || kindWindow("captcha", 1, 2) != 2 || kindWindow("rebind", 1, 2) != 2 {
		t.Error("kindWindow: pow and passthrough take the proof-of-work window, captcha and rebind the CAPTCHA window")
	}
}
