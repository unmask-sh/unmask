package outbound

import (
	"net/netip"
	"strings"
	"testing"
)

// SetOnlyLoopbackForTests: with it on, a destination that is not loopback is
// refused under every policy, a local-by-design caller's too -- for the
// policy's own reason where it has one, for the suite's where the policy
// would have let it through; loopback goes by the rules it had.  Off again,
// the policy alone decides.
func TestOnlyLoopbackForTests(t *testing.T) {
	was := SetOnlyLoopbackForTests(true)
	t.Cleanup(func() { SetOnlyLoopbackForTests(was) })
	for _, p := range []Policy{{}, {AllowLoopback: true}, {DenyPrivate: true}} {
		for _, addr := range []string{"203.0.113.1", "192.168.1.5", "2001:db8::1", "::ffff:203.0.113.1", "64:ff9b::203.0.113.1"} {
			for _, local := range []bool{false, true} {
				why := p.Refuse(netip.MustParseAddr(addr), local)
				want := "loopback only"
				if p.DenyPrivate && addr == "192.168.1.5" {
					want = "outbound.deny_private"
				}
				if !strings.Contains(why, want) {
					t.Errorf("policy %+v, %s (local %v): %q, want a refusal naming %q", p, addr, local, why, want)
				}
			}
		}
	}
	if why := (Policy{}).Refuse(netip.MustParseAddr("169.254.169.254"), false); why != "cloud metadata address" {
		t.Errorf("the metadata address keeps its own reason: %q", why)
	}
	if why := (Policy{AllowLoopback: true}).Refuse(netip.MustParseAddr("127.0.0.1"), false); why != "" {
		t.Errorf("loopback under a policy that allows it: refused (%s)", why)
	}
	if why := (Policy{}).Refuse(netip.MustParseAddr("::1"), true); why != "" {
		t.Errorf("loopback for a local-by-design caller: refused (%s)", why)
	}
	// The metadata addresses keep their own reason: it is the one a
	// production log shows.
	if why := (Policy{}).Refuse(netip.MustParseAddr("0.0.0.0"), false); why != "not an address" {
		t.Errorf("the unspecified address: %q", why)
	}

	SetOnlyLoopbackForTests(false)
	if why := (Policy{}).Refuse(netip.MustParseAddr("203.0.113.1"), false); why != "" {
		t.Errorf("switched off, a public address is refused: %s", why)
	}
}
