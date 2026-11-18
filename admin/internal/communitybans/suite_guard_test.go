package communitybans

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The suite cannot reach a host that is not loopback (TestMain): a client
// left on the hub's default address fails to connect, it does not register.
func TestSuiteReachesLoopbackOnly(t *testing.T) {
	var cur settings.Settings
	cur.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
	// The address of no host (TEST-NET-3), named outright so that nothing is
	// asked of a resolver either; the default would be the hub's own name.
	cur.CommunityBans.RegisterURL = "http://203.0.113.1/api/feed/register"
	cur.CommunityBans.FeedURL = "http://203.0.113.1/api/feed/list.json"
	c := &Client{
		UserAgent:      "unmask-test",
		SettingsGetter: func() settings.Settings { return cur },
		SettingsUpdate: func(f func(*settings.Settings)) error { f(&cur); return nil },
		MapDir:         t.TempDir(),
	}
	err := c.Register(t.Context())
	if err == nil || !strings.Contains(err.Error(), "reaches loopback only") {
		t.Fatalf("Register to an address that is not loopback: err %v, want the suite's refusal", err)
	}
	if cur.CommunityBans.Token != "" {
		t.Errorf("a token was stored: %q", cur.CommunityBans.Token)
	}
	if _, err := c.Pull(t.Context()); err == nil || !strings.Contains(err.Error(), "reaches loopback only") {
		t.Errorf("Pull from an address that is not loopback: err %v, want the suite's refusal", err)
	}
}
