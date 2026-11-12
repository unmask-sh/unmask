package ban

import (
	"context"
	"os"
	"strings"
	"testing"
)

// A relay's exit -- iCloud Private Relay, a secure web gateway -- is one
// address for everyone the relay sends out through it.  An automatic ban
// there (one visitor's request to a trap) banned them all.  None is placed;
// an operator's own ban is, and a ban that was there already stays in force
// until it runs out.
func TestRelayExitGetsNoAutomaticBan(t *testing.T) {
	mgr, banFile := egressManager(t)
	mgr.SetEgress(nil)
	relayExit := func(ip string) (string, bool) {
		if strings.HasPrefix(ip, "172.224.226.") {
			return "iCloud Private Relay", true
		}
		return "", false
	}
	ctx := context.Background()
	const exit, ja4 = "172.224.226.5", "t13d230800_bfd000000000_000000000000"

	// A ban from before the address was known for a relay's: placed.
	mgr.Add(exit, ja4)
	if _, _, b := mgr.IsBannedActionSource(ctx, exit, ja4); !b {
		t.Fatal("setup: the address was not banned while it was nobody's")
	}

	mgr.SetSharedExit(relayExit)
	// It stays in force, and in the file.
	mgr.settle()
	if _, _, b := mgr.IsBannedActionSource(ctx, exit, ja4); !b {
		t.Error("a ban that was there already was dropped once the address was a relay's")
	}
	if buf, _ := os.ReadFile(banFile); !strings.Contains(string(buf), exit+"|"+ja4) {
		t.Errorf("the earlier ban left the file:\n%s", buf)
	}

	// New automatic bans on the exit: none, by any of the ways one is placed.
	const other = "172.224.226.9"
	mgr.Add(other, ja4)
	mgr.AddAuto(ctx, other, ja4, ScopeIPJA4, SourceRateLimitAbuse, "pass budget", "captcha_only", 3600)
	mgr.AddAuto(ctx, other, "", ScopeIPOnly, SourceRateLimitAbuse, "pass budget", "deny", 3600)
	if _, _, b := mgr.IsBannedActionSource(ctx, other, ja4); b {
		t.Fatal("an automatic ban landed on a relay's exit")
	}
	for _, e := range mgr.Snapshot() {
		if e.IP == other {
			t.Fatalf("a row for the relay's exit: %+v", e)
		}
	}
	// Another address is banned as before.
	mgr.Add("203.0.113.9", ja4)
	if _, _, b := mgr.IsBannedActionSource(ctx, "203.0.113.9", ja4); !b {
		t.Fatal("a plain address was not banned")
	}
	// The operator's own ban on the exit holds.
	if err := mgr.AddManual(ctx, other, ja4, "by hand", "alice", "deny", 0); err != nil {
		t.Fatal(err)
	}
	if _, src, b := mgr.IsBannedActionSource(ctx, other, ja4); !b || src != "manual" {
		t.Fatalf("the operator's ban on the relay's exit: banned=%v source=%q", b, src)
	}
	// And with the lookup taken away (the relay list switched off), the
	// address is banned like any other.
	mgr.SetSharedExit(nil)
	mgr.Add("172.224.226.77", ja4)
	if _, _, b := mgr.IsBannedActionSource(ctx, "172.224.226.77", ja4); !b {
		t.Error("with the relay list off, the address was still spared")
	}
}
