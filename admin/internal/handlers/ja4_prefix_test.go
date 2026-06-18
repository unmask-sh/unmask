package handlers

import "testing"

// TestJA4Prefix pins the roaming-rebind fingerprint rule: keep JA4_a_JA4_b
// (version + cipher) and drop the JA4_c extension hash, which Chrome varies per
// connection.  The two real JA4s below came from one Android device within an
// hour and must collapse to the same prefix so its _bvj keeps matching.
func TestJA4Prefix(t *testing.T) {
	for _, c := range []struct {
		name, in, want string
	}{
		{"full", "q13d0312h3_55b375c5d22e_5a06198afb93", "q13d0312h3_55b375c5d22e"},
		{"same device, different extension hash", "q13d0312h3_55b375c5d22e_151122171f7d", "q13d0312h3_55b375c5d22e"},
		{"already a prefix", "q13d0312h3_55b375c5d22e", "q13d0312h3_55b375c5d22e"},
		{"single segment", "q13d0312h3", "q13d0312h3"},
		{"empty", "", ""},
		{"trailing underscore only", "q13d0312h3_", "q13d0312h3_"},
	} {
		if got := ja4Prefix(c.in); got != c.want {
			t.Errorf("%s: ja4Prefix(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}

	// The whole point: two extension-hash variants of one device share a prefix.
	a := ja4Prefix("q13d0312h3_55b375c5d22e_5a06198afb93")
	b := ja4Prefix("q13d0312h3_55b375c5d22e_178839b6cec1")
	if a != b {
		t.Errorf("same-device JA4 variants must share a prefix: %q != %q", a, b)
	}
}
