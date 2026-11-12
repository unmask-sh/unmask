package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// BanSharedExit is what the ban manager asks before it places an automatic
// ban: is this address a relay's exit, shared by everyone the relay sends
// out through it?  It answers from the relay list while the list is in use.
func TestBanSharedExitReadsTheRelayList(t *testing.T) {
	h := newTestHandler(t)
	tb, err := relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-13T00:00:00Z","relays":{"apple-private-relay":{"countries":{"JP":["172.224.226.0/27"]}},"zscaler":{"bind":"relay","ranges":["2001:db8:5c::/48"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	t.Cleanup(func() { relay.Set(nil); relay.SetOff(nil) })

	for ip, want := range map[string]string{
		"172.224.226.5":  "iCloud Private Relay",
		"2001:db8:5c::9": "Zscaler",
		"203.0.113.10":   "",
		"not-an-address": "",
		"":               "",
	} {
		name, ok := h.BanSharedExit(ip)
		if (want != "") != ok || name != want {
			t.Errorf("BanSharedExit(%q) = %q, %v; want %q", ip, name, ok, want)
		}
	}
	// The operator's switch for the relay list takes this with it.
	relay.SetOff(func() bool { return true })
	if name, ok := h.BanSharedExit("172.224.226.5"); ok {
		t.Errorf("with the relay list off, the address is still a relay's (%q)", name)
	}
}
