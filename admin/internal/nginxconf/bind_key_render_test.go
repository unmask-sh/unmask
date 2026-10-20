package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// The pass cookie's bind key: http.inc gives $unmask_bind_key the published
// relay range for a client inside one, and server.inc hands the variable to the
// daemon, so the plugin and the issuer bind to the same value.
func TestBindKeyRender(t *testing.T) {
	tb, err := relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-19T00:00:00Z","relays":{"r":{"name":"r","source":"test","countries":{"JP":["192.0.2.192/26","2001:db8:f00::/48"],"US":["198.51.100.0/25"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	defer relay.Set(nil)

	httpInc, serverInc, _ := renderIncs(t, nil)
	for _, want := range []string{
		"geo $remote_addr $unmask_bind_key {",
		`    192.0.2.192/26 "192.0.2.192/26";`,
		`    198.51.100.0/25 "198.51.100.0/25";`,
		`    2001:db8:f00::/48 "2001:db8:f00::/48";`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	if !strings.Contains(serverInc, "proxy_set_header   X-Unmask-Bind-Key $unmask_bind_key;") {
		t.Error("server.inc does not forward $unmask_bind_key to the daemon")
	}

	// A relay bound as a whole: every one of its ranges is valued with the
	// relay's id, so a cookie issued inside one range verifies inside another.
	tb, err = relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-20T00:00:00Z","relays":{"zscaler":{"name":"Zscaler","source":"test","bind":"relay","ranges":["165.225.96.0/23","136.226.238.0/23"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	httpInc, _, _ = renderIncs(t, nil)
	for _, want := range []string{
		`    136.226.238.0/23 "zscaler";`,
		`    165.225.96.0/23 "zscaler";`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}

	// Without a relay list the block still defines the variable, empty, so the
	// header in server.inc always resolves.
	relay.Set(nil)
	httpInc, _, _ = renderIncs(t, nil)
	i := strings.Index(httpInc, "geo $remote_addr $unmask_bind_key {")
	if i < 0 {
		t.Fatal("http.inc lacks the bind-key block without a relay list")
	}
	body := httpInc[i:]
	body = body[:strings.Index(body, "\n}")]
	if strings.Contains(body, "/") {
		t.Errorf("the bind-key block must be empty without a relay list, got %q", body)
	}
}
