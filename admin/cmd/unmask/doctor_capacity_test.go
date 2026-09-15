package main

import "testing"

// The database against the box: half the memory is the line, and the message
// has to name the consequence rather than just the number.
func TestDBMemoryVerdict(t *testing.T) {
	const gb = int64(1) << 30
	if warn, msg := dbMemoryVerdict(2*gb, 3*gb, 8*gb); warn || msg == "" {
		t.Errorf("a quarter of memory is fine: warn=%v %q", warn, msg)
	}
	if warn, _ := dbMemoryVerdict(4*gb, 4*gb, 8*gb); warn {
		t.Error("exactly half is still fine")
	}
	warn, msg := dbMemoryVerdict(4*gb+1, 5*gb, 8*gb)
	if !warn {
		t.Fatal("past half must warn")
	}
	for _, want := range []string{"evicts", "events_retention_days", "of memory"} {
		if !contains(msg, want) {
			t.Errorf("message must say %q: %s", want, msg)
		}
	}
	// The file being larger than what is live is normal after a prune; the
	// judgement is on the live bytes, and both are reported.
	if warn, msg := dbMemoryVerdict(1*gb, 30*gb, 8*gb); warn || !contains(msg, "on disk") {
		t.Errorf("free pages are not a reason to warn: warn=%v %q", warn, msg)
	}
	// An unknown limit is not a finding: say the size and stop.
	if warn, msg := dbMemoryVerdict(9*gb, 9*gb, 0); warn || !contains(msg, "unknown") {
		t.Errorf("unknown memory limit: warn=%v %q", warn, msg)
	}
}

// The gateway container: the published sample's defaults are the finding,
// and a configured deployment says so quietly.
func TestGatewaySampleVerdict(t *testing.T) {
	// The 2026-09-13 shape: both defaults in place.
	warn, msg := gatewaySampleVerdict(map[string]string{
		"upstream_env": "http://app:80", "server_name_env": "localhost",
	})
	if !warn {
		t.Fatal("the sample stack must be a finding")
	}
	for _, want := range []string{"example app", "TLS handshake", "override"} {
		if !contains(msg, want) {
			t.Errorf("message must say %q: %s", want, msg)
		}
	}
	// One of the two is enough.
	if warn, _ := gatewaySampleVerdict(map[string]string{"upstream_env": "http://app:80", "server_name_env": "_"}); !warn {
		t.Error("the sample upstream alone is a finding")
	}
	if warn, _ := gatewaySampleVerdict(map[string]string{"upstream_env": "http://origin:8080", "server_name_env": "localhost"}); !warn {
		t.Error("answering for localhost alone is a finding")
	}
	// A deployment: its own origin, answering for everything.
	warn, msg = gatewaySampleVerdict(map[string]string{
		"upstream_env": "http://host.docker.internal:8080", "server_name_env": "_",
	})
	if warn {
		t.Errorf("a configured gateway is not a finding: %s", msg)
	}
	if !contains(msg, "host.docker.internal:8080") || !contains(msg, "_") {
		t.Errorf("the ok line names what it found: %s", msg)
	}
	// The upstream set on the Gateway tab leaves the environment empty.
	if warn, msg := gatewaySampleVerdict(map[string]string{"location_source": "admin"}); warn || !contains(msg, "Gateway tab") {
		t.Errorf("an admin-rendered upstream: warn=%v %q", warn, msg)
	}
	// An older nginx image writes no server name: judge on what is there.
	if warn, _ := gatewaySampleVerdict(map[string]string{"upstream_env": "http://origin:8080"}); warn {
		t.Error("a missing server_name_env is not a finding")
	}
}

func TestUpstreamHost(t *testing.T) {
	for in, want := range map[string]string{
		"http://app:80":                    "app",
		"app":                              "app",
		"http://host.docker.internal:8080": "host.docker.internal",
		"https://origin.example/path":      "origin.example",
		"":                                 "",
	} {
		if got := upstreamHost(in); got != want {
			t.Errorf("upstreamHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
