package settings

import "testing"

// TestAccessLogOn: unset and "on" log, "off" and its spellings do not.
func TestAccessLogOn(t *testing.T) {
	for v, want := range map[string]bool{"": true, "on": true, "yes": true, "off": false, "OFF": false, " false ": false, "no": false, "0": false} {
		if got := (Server{AccessLog: v}).AccessLogOn(); got != want {
			t.Errorf("access_log %q: on=%v, want %v", v, got, want)
		}
	}
}
